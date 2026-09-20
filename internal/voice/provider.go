package voice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// Verdict is what a provider makes of a clip.
type Verdict struct {
	Transcript string  `json:"transcript"`
	Category   string  `json:"category"`
	Score      float64 `json:"score"`
	Summary    string  `json:"summary"`
	Provider   string  `json:"provider"`
}

// Meta travels with the clip. The called number never does.
type Meta struct {
	From     string
	Customer string
	Language string
	Report   bool
}

// Provider transcribes and classifies. Implementations: any
// OpenAI-compatible pair of endpoints, or the CallerAPI scan API.
type Provider interface {
	Name() string
	Analyse(ctx context.Context, wav []byte, meta Meta) (Verdict, error)
}

// Categories is the CallerAPI complaint list. A verdict must use one of
// these so a scam found here files under the same subject everywhere.
var Categories = []string{
	"Advance Fee Loan", "Bank/Credit Card Company Imposter", "Business Email Compromise",
	"Calls pretending to be government, businesses, or family and friends", "Charity",
	"Computer & Technical Support", "Counterfeit Product", "COVID-19", "Credit Cards",
	"Credit Repair/Debt Relief", "Cryptocurrency", "Debt Collection", "Lotteries, Prizes & Sweepstakes",
	"Medical & Prescriptions", "Moving", "No Subject Provided", "Phishing",
	"Reducing Your Debt (Credit Cards, Mortgage, Student Loans)", "Rental", "Romance", "Tax Collection",
	"Travel/Vacation/Timeshare", "Utility", "Warranties & Protection Plans",
	"Work From Home & Other Ways To Make Money", "Yellow Pages/Directories", "Hang Up", "Scammers",
	"Advertising", "Surveys", "Financial Services", "Store", "Company", "Other",
}

// IsScamCategory reports whether a category is one an operator acts on.
// Store, Company, Surveys, and Advertising are unwanted at worst.
func IsScamCategory(c string) bool {
	switch strings.TrimSpace(c) {
	case "", "Store", "Company", "Surveys", "Advertising", "Hang Up", "No Subject Provided", "Other", "none":
		return false
	}
	for _, k := range Categories {
		if k == c {
			return true
		}
	}
	return false
}

// OpenAICompat talks to any server that speaks the OpenAI audio and chat
// APIs: OpenAI, Groq, xAI for chat, a local Whisper server for speech.
// STT and chat may point at different servers and keys.
type OpenAICompat struct {
	STTBaseURL  string
	STTAPIKey   string
	STTModel    string
	ChatBaseURL string
	ChatAPIKey  string
	ChatModel   string
	HTTP        *http.Client
}

func (o *OpenAICompat) Name() string { return "openai-compatible:" + o.ChatModel }

func (o *OpenAICompat) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return &http.Client{Timeout: 90 * time.Second}
}

func (o *OpenAICompat) Analyse(ctx context.Context, wav []byte, meta Meta) (Verdict, error) {
	text, err := o.transcribe(ctx, wav, meta.Language)
	if err != nil {
		return Verdict{Provider: o.Name()}, err
	}
	v, err := o.classify(ctx, text)
	v.Transcript = text
	v.Provider = o.Name()
	return v, err
}

func (o *OpenAICompat) transcribe(ctx context.Context, wav []byte, language string) (string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "clip.wav")
	_, _ = fw.Write(wav)
	_ = mw.WriteField("model", firstNonEmpty(o.STTModel, "whisper-1"))
	_ = mw.WriteField("response_format", "json")
	if language != "" {
		_ = mw.WriteField("language", language)
	}
	_ = mw.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.STTBaseURL, "/")+"/audio/transcriptions", &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if o.STTAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.STTAPIKey)
	}
	resp, err := o.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("stt %s: %s", resp.Status, trim(raw))
	}
	var out struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("stt: %w", err)
	}
	return strings.TrimSpace(out.Text), nil
}

const classifyPrompt = `You classify the opening of a phone call for a telephone carrier's fraud desk.
Decide whether the caller is running a scam or unwanted robocall, and which category from the list fits best.
Return only JSON: {"category": "<one of the list, or none>", "score": <0 to 1 probability that this is a scam or illegal robocall>, "summary": "<one sentence, what the caller wants>"}.
Categories: %s.
Use "none" for an ordinary personal or business call. Do not guess a scam from a short or unclear transcript; give a low score instead.`

func (o *OpenAICompat) classify(ctx context.Context, transcript string) (Verdict, error) {
	if strings.TrimSpace(transcript) == "" {
		return Verdict{Category: "none"}, nil
	}
	payload := map[string]any{
		"model":           firstNonEmpty(o.ChatModel, "gpt-4o-mini"),
		"temperature":     0.1,
		"response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{
			{"role": "system", "content": fmt.Sprintf(classifyPrompt, strings.Join(Categories, "; "))},
			{"role": "user", "content": "Transcript:\n" + transcript},
		},
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.ChatBaseURL, "/")+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.ChatAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.ChatAPIKey)
	}
	resp, err := o.client().Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return Verdict{}, fmt.Errorf("chat %s: %s", resp.Status, trim(raw))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return Verdict{}, errors.New("chat: empty response")
	}
	var v struct {
		Category string  `json:"category"`
		Score    float64 `json:"score"`
		Summary  string  `json:"summary"`
	}
	content := strings.TrimSpace(out.Choices[0].Message.Content)
	content = strings.TrimPrefix(strings.TrimSuffix(content, "```"), "```json")
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &v); err != nil {
		return Verdict{}, fmt.Errorf("chat: %w", err)
	}
	return Verdict{Category: canonical(v.Category), Score: clamp(v.Score), Summary: v.Summary}, nil
}

// CallerAPI sends the clip to the CallerAPI voice scan API, which
// transcribes and classifies with the same taxonomy and, when Report is
// on, files the calling number for a scam verdict.
type CallerAPI struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func (c *CallerAPI) Name() string { return "callerapi" }

func (c *CallerAPI) Analyse(ctx context.Context, wav []byte, meta Meta) (Verdict, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("audio", "clip.wav")
	_, _ = fw.Write(wav)
	_ = mw.WriteField("encoding", "wav")
	if meta.From != "" {
		_ = mw.WriteField("from", meta.From)
	}
	if meta.Language != "" {
		_ = mw.WriteField("language", meta.Language)
	}
	if meta.Report {
		_ = mw.WriteField("report", "true")
	}
	_ = mw.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/api/voice/scan", &body)
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Auth", c.APIKey)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return Verdict{}, fmt.Errorf("callerapi scan %s: %s", resp.Status, trim(raw))
	}
	var out struct {
		Transcript string `json:"transcript"`
		Verdict    struct {
			Score    float64 `json:"score"`
			Category string  `json:"category"`
			Summary  string  `json:"summary"`
		} `json:"verdict"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Verdict{}, err
	}
	return Verdict{Transcript: out.Transcript, Category: canonical(out.Verdict.Category), Score: clamp(out.Verdict.Score), Summary: out.Verdict.Summary, Provider: "callerapi"}, nil
}

func canonical(c string) string {
	c = strings.TrimSpace(c)
	for _, k := range Categories {
		if strings.EqualFold(k, c) {
			return k
		}
	}
	if c == "" {
		return "none"
	}
	return c
}

func clamp(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

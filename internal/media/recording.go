package media

// Recording is a finished call recording handed to the voice pipeline.
// Path is relative to the recordings folder. The left channel is the
// caller and the right channel is the callee.
type Recording struct {
	CallID      string
	MediaCallID int64
	From        string
	To          string
	Path        string
	Seconds     float64
}

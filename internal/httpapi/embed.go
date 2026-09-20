package httpapi

import "embed"

//go:embed web/*
var webRoot embed.FS

func WebFS() embed.FS {
	return webRoot
}

package cli

import "os"

// isTTY reports whether w is a terminal. Bytes-buffer / *os.File-pointing-
// at-pipe both return false; only an *os.File whose fd is a real TTY
// returns true. We use it for two things: deciding when to colorize the
// table output, and detecting whether stdin has been piped.
func isTTY(w any) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}

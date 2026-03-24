//go:build !windows

package wintool

const errNotSupported = "wintool is only supported on Windows"

func opList(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opTree(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opFind(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opInspect(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opScreenshot(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opGettext(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opSettext(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opClick(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opType(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opSend(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opShow(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opMove(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opClose(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opFocus(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

func opClipboard(input WintoolInput) (*CallResult, WintoolOutput, error) {
	return errorResult(errNotSupported)
}

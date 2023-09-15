package fhevm

import "fmt"

// A Logger interface for the EVM.
type Logger interface {
	Debug(msg string, keyvals ...interface{})
	Info(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
}

// A default Logger implementation that logs to stdout.
type DefaultLogger struct{}

func toString(keyvals ...interface{}) (ret string) {
	for _, element := range keyvals {
		ret += fmt.Sprintf("%v", element) + " "
	}
	return
}

func (*DefaultLogger) Debug(msg string, keyvals ...interface{}) {
	fmt.Println("Debug: "+msg, toString(keyvals...))
}

func (*DefaultLogger) Info(msg string, keyvals ...interface{}) {
	fmt.Println("Info: "+msg, toString(keyvals...))
}

func (*DefaultLogger) Error(msg string, keyvals ...interface{}) {
	fmt.Println("Error: "+msg, toString(keyvals...))
}

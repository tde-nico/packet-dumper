package main

import (
	"fmt"
)

// Waring: This function blocks until new line is printed on terminal
/*
func get_cursor() (int, int) {
	var row, col int
	fmt.Print("\033[6n")
	fmt.Scanf("\033[%d;%dR", &row, &col)
	return row, col
}
*/

var INLINE bool

func clear_screen() {
	if !INLINE {
		return
	}
	fmt.Print("\033[2J")
}

func clear_line() {
	if !INLINE {
		fmt.Println("")
		return
	}
	fmt.Print("\033[K")
}

func move_cursor(row, col int) {
	if !INLINE {
		return
	}
	fmt.Printf("\033[%d;%dH", row, col)
}

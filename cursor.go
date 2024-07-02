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

func clear_screen() {
	fmt.Print("\033[2J")
}

func clear_line() {
	fmt.Print("\033[K")
}

func move_cursor(row, col int) {
	fmt.Printf("\033[%d;%dH", row, col)
}

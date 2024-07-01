package main

import (
	"log"
	"strconv"
	"strings"
	"time"
)

func ljust(s string, n int, fill string) string {
	return s + strings.Repeat(fill, n-len(s))
}

func format_time(s string) string {
	ct := time.Now()
	n := strings.ReplaceAll(s, "%Y", strconv.Itoa(ct.Year()))
	n = strings.ReplaceAll(n, "%m", ljust(strconv.Itoa(int(ct.Month())), 2, "0"))
	n = strings.ReplaceAll(n, "%d", ljust(strconv.Itoa(ct.Day()), 2, "0"))
	n = strings.ReplaceAll(n, "%H", ljust(strconv.Itoa(ct.Hour()), 2, "0"))
	n = strings.ReplaceAll(n, "%M", ljust(strconv.Itoa(ct.Minute()), 2, "0"))
	n = strings.ReplaceAll(n, "%S", ljust(strconv.Itoa(ct.Second()), 2, "0"))
	return n
}

func check(e error, m string) {
	if e != nil {
		log.Fatalf(m, e)
	}
}

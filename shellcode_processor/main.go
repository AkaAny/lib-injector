package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

func main() {
	cmd := exec.Command("objdump", "--disassemble-all", "shellcode.o")
	var stdout = bytes.NewBuffer(nil)
	var stderr = bytes.NewBuffer(nil)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		println(stderr.String())
		panic(err)
	}
	var outStr = stdout.String()

	var partHeaderExpr = regexp.MustCompile(`.+ <.+>:`)
	outStr = partHeaderExpr.ReplaceAllStringFunc(outStr, func(old string) string {
		return "//" + old
	})
	var insnLineExpr = regexp.MustCompile(`([0-9A-Fa-f]+): (.+)  	(.+)`)
	outStr = insnLineExpr.ReplaceAllStringFunc(outStr, func(old string) string {
		var result = old
		var parts = insnLineExpr.FindStringSubmatch(result)[1:]
		offsetPrefix, insnHex, disasmStr := parts[0], parts[1], parts[2]
		var insnBytes = strings.Split(insnHex, " ")
		for i := 0; i < len(insnBytes); i++ {
			insnBytes[i] = "0x" + insnBytes[i]
		}
		insnHex = strings.Join(insnBytes, ",") + ","
		result = insnHex + " //" + "+" + offsetPrefix + ":	" + disasmStr
		return result
	})
	//result = "0x" + result
	//		var spaceExpr = regexp.MustCompile(` `)
	//		result = spaceExpr.ReplaceAllString(result, ",0x")
	fmt.Println(outStr)
}

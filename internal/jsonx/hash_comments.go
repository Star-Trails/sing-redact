package jsonx

func stripHashComments(input []byte) []byte {
	output := append([]byte(nil), input...)
	const (
		stateContent = iota
		stateString
		stateStringEscape
		stateLineComment
		stateBlockComment
		stateBlockCommentStar
	)
	state := stateContent
	for index := range output {
		character := output[index]
		switch state {
		case stateContent:
			switch character {
			case '"':
				state = stateString
			case '#':
				output[index] = ' '
				state = stateLineComment
			case '/':
				if index+1 < len(output) && output[index+1] == '/' {
					state = stateLineComment
				} else if index+1 < len(output) && output[index+1] == '*' {
					state = stateBlockComment
				}
			}
		case stateString:
			if character == '\\' {
				state = stateStringEscape
			} else if character == '"' {
				state = stateContent
			}
		case stateStringEscape:
			state = stateString
		case stateLineComment:
			if character == '\n' || character == '\r' {
				state = stateContent
			} else if output[index] != '/' {
				output[index] = ' '
			}
		case stateBlockComment:
			if character == '*' {
				state = stateBlockCommentStar
			}
		case stateBlockCommentStar:
			if character == '/' {
				state = stateContent
			} else if character != '*' {
				state = stateBlockComment
			}
		}
	}
	return output
}

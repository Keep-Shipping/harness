; Keys — the colon is part of the token, so it wears the key's colour.
(key) @property

; `and or not is` are reserved; scalars and operators are their own classes.
(keyword) @keyword.operator
(operator) @operator
(operator) @keyword.operator

(boolean) @boolean
(duration) @number
(number) @number
(handle) @constant

; Strings, and the interpolation holes inside words and strings alike.
(string) @string
(escape) @string.escape
(interpolation) @string.special
(interpolation (dotted_name)) @variable

(comment) @comment

(punctuation) @punctuation.delimiter
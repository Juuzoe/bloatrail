# The README's hero GIF: what Bloatrail is, in about twenty seconds.
#
# Recorded with VHS (https://github.com/charmbracelet/vhs):
#
#     python docs/demo/fixture.py ~/Projects
#     vhs docs/demo/hero.tape
#
# The story is deliberately one beat: any tool can sort by size, but only this
# one knows that two directories with the same name are not the same thing.

Output docs/demo/hero.gif

Require bloatrail

Set Shell bash
Set FontSize 15
Set Width 1300
Set Height 860
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set WindowBar Colorful
Set BorderRadius 8

Hide
Type "clear" Enter
Show

# 1. Where did it go? Nothing surprising yet — this is what `du` also tells you.
Type "bloatrail scan ~/Projects"
Sleep 600ms
Enter
Sleep 4s

Type "clear" Enter
Sleep 300ms

# 2. The column du cannot write: what IS this, and may I remove it?
Type "bloatrail explain ~/Projects/backend-api/target"
Sleep 600ms
Enter
Sleep 4500ms

Type "clear" Enter
Sleep 300ms

# 3. The same name, the opposite verdict — because the evidence differs.
Type "bloatrail explain ~/Projects/marketing/target"
Sleep 600ms
Enter
Sleep 4500ms

Type "clear" Enter
Sleep 300ms

# 4. And so the cleanup offers one and refuses the other.
Type "bloatrail clean ~/Projects --dry-run"
Sleep 600ms
Enter
Sleep 5s

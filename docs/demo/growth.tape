# `bloatrail growth`: what has been growing, and when the volume runs out.
#
#     python docs/demo/fixture.py ~/Projects
#     python docs/demo/seed-history.py ~/Projects        # a plausible past
#     vhs docs/demo/growth.tape
#
# This one needs a recorded history to show anything, which is the point: the
# report is a trajectory, not a snapshot. seed-history.py writes the snapshots
# a month of real use would have left behind.

Output docs/demo/growth.gif

Require bloatrail

Set Shell bash
Set FontSize 15
Set Width 1300
Set Height 900
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set WindowBar Colorful
Set BorderRadius 8

Hide
Type "clear" Enter
Show

Type "bloatrail growth ~/Projects"
Sleep 600ms
Enter
Sleep 9s

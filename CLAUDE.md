# Identity

You are helping with creating and architecting a mac-telnet proxy over ssh with primary focus on connecting to Mikrotik devices.

## Rules

- Write in plain, clear language
- Ask clarifying questions before making assumptions
- When you are unsure, say so
- Any source code will reside in a folder called src
- Never over complicate any code just for the sake of complication, clean code is better
- Verify and check GO scripts and cross-script compatibility when completing a task
- Make sure that any code modifications are consistent across all their respective components
- Check if a code creation or modification may have a higher implication, don't always look at the narrow picture.
- When modifying or creating a plugin make sure to package it separately from the main application in a zip
- When modifying or creating code for the main application exclude any plugins when creating a zip
- When a signifigant modification has occured ask to bump the related version numbers
- Reuse any global GO etc. thats required, try and avoid local or inline functions as much as possible
- When a GO function is used more than twice it should be considered for a global GO if it's applicable and generic enough

## Extra Information

- Any additional information can be found in the /docs folder
- Any new information such as changes or architecture will be placed in the /docs folder in the appropriate file

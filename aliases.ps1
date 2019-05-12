## Navigation
${function:~} = { Set-Location ~ }
${function:Set-ParentLocation} = { Set-Location .. }; Set-Alias ".." Set-ParentLocation
${function:...} = { Set-Location ..\.. }
${function:....} = { Set-Location ..\..\.. }
${function:.....} = { Set-Location ..\..\..\.. }
${function:......} = { Set-Location ..\..\..\..\.. }

## Navigation Shortcuts
${function:dl} = { Set-Location ~\Downloads }
${function:docs} = { Set-Location ~\Documents }
${function:dot} = { Set-Location ~\Documents\WindowsPowerShell }
${function:appd} = { Set-Location ~\AppData\Roaming }

## Update installed Ruby Gems, NPM, and their installed packages.
Set-Alias update System-Update

## Create a new directory and enter it
Set-Alias mkd CreateAndSet-Directory

## Vim
Set-Alias v vim

## ls
Set-Alias l ls

## Open
Set-Alias o ii

## Drives
${function:df} = { gdr -PSProvider 'FileSystem' }

## List PowerShell's Environmental Variables
${function:env} = { Get-Childitem -Path Env:* | Sort-Object Name }

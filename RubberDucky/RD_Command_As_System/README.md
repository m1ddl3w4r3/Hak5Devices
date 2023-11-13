# Command_As_System

## Description
Will create a system level powershell process and run the command provided.

##NOTES: \
	- Assumes user has local admin access. \
	- Assumes UAC is set to always notify. but will work either way. \
	- This is to make sure you read the stuff you run. and to comply with the hak5 TOS regarding staged payloads.
```
	- Replace example.com with code below hosetd on your own infrastructure (Github is not a CDN for deployments)
https://raw.githubusercontent.com/mkellerman\/Invoke-CommandAs/master/Invoke-CommandAs/
```

	


##OPSEC: \
	- Will create a scheduled task to elevate. \
	- Will download mkellerman's Invoke-CommandAs repo from github.

## Getting Started

Edit payload.txt to your liking. (SEE ABOVE) \
Upload payload.txt to payload studio and generate the payload. 
Copy inject.bin to the root of RuberDucky. \
Plug it into client computer. \
(Because we have permission right?.... Right?)

### Dependencies

* Windows 10,11

### Executing program

* Plug in your device
* Command will be entered in the system level powershell window.

## Contributing

All contributors names will be listed here

m1ddl3w4r3

## Version History

* 0.1
    * Initial Release

## Acknowledgments

mkellerman - https://github.com/mkellerman/Invoke-CommandAs.git

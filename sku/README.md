# wslp-sku

This script utility is used to create the base image used for the challenge.
First download an Windows 11 Home ISO, and then pass that file to this script
and it will prepare the image for usage. Once completed, it will create an
install image VHDX that can be used to install the challenge setup, and a
separate output VHDX that can be used to run the challenge VM.

A few quick notes of clarifications on the installation process:
* Once the script kicks off the job, you must click through some steps
  in the windows setup in order to start the installation process.
* On the disk selection step, make sure to select the disk that is ~20GB in size
* Yes, you can install windows in a ~20GB hard-drive even if it might be nagging
  at you a bit that it can't install it.
* We used 24H2 as our base image

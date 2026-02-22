# Cybersec-practice
The scripts in this repository have been created for educational purposes so that you can quickly set up a random environment to test your skills at making a computer more secure. This is designed to help you practice on your own time for cyber security competitions such as Cyberpatriot.

Quick start instructions:
1. Download start.ps1 to a Windows 11 virtual machine and put it in a folder location that is easy to access like c:\temp, then run it as administrator and update everything from the Updates page.  
2. Restart the script and click to install the Cybersec Prerequisites.
3. Take a snapshot of the VM.
4. Launch the script from the Desktop Shortcut.
5. Click Run Cybersec Practice Setup.ps1.
6. Read the README file placed on the desktop and secure the VM based on that document.
7. Check your score using the Run Open score card.ps1
8. Restore the VM snapshot and run the setup again.

Please read the Wiki for detailed setup instructions.

These scripts will set random requirements and give you a readme with information that you will use to identify what needs to be completed to make the computer more secure.

The instructions provided to create and configure Virtual Machines are written with VMware Workstation in mind, but the scripts should work on any hypervisor.

CAUTION!!!! These scripts are not designed to be run on physical hardware because they can install malware, tracking software, and change security settings that would open vectors of attack. If you accidentally run a script that could harm your computer, you will get a confirmation warning before continuing, but in case your virtualization environment fails to be detected properly you can still install it if you choose to do so (you just have a mess to clean up if you run it on your physical PC).

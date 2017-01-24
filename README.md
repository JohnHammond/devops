DevOps
===========

> John Hammond | Started January 24th, 2017

------------


This is my attempt to work with DevOps and system administration. I hope to document things I find or get stuck on here in this repository. It is ultimately a scratchpad; but at least one that can be archived and searched through.


----------


Your PC ran into a problem and needs to restart (Windows 10)
--------

This error shows up too often on my own host machine, and I need to fix it. Research has led me here: [http://dowser.org/pc-ran-problem-needs-restart-windows-10-fix-guide/](http://dowser.org/pc-ran-problem-needs-restart-windows-10-fix-guide/)

* It explains you should download the [BlueScreenView] view from [Nirsoft].
* You have to configure your system to save the MiniDump files after an error.
    - `Control Panel` -> `System and Security` -> `System` -> `Advanced System Settings` -> `Advanced` -> `Setup` and choose `Small Memory Dump`.
* Run the [BlueScreenView] after the error has occured to find the dump process.

Then hopefully find some research points to solve the problem.


Adding a Windows client to a Domain
----------------------------------

I've been trying to add a Windows 10 or Windows 8 host to my Windows Server 2016 domain... and I have admittedly been struggling with it.

I have found what you have to do is set the [DNS] nameserver of the client machine to the Windows Server itself.

-------------








[BlueScreenView]: http://www.nirsoft.net/utils/blue_screen_view.html
[Nirsoft]: http://www.nirsoft.net/
[DNS]: https://en.wikipedia.org/wiki/Domain_Name_System
[Domain Name System]: https://en.wikipedia.org/wiki/Domain_Name_System
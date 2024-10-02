<h1 align="center">
  <br>
  <a href="https://github.com/V31L0X1/"><img src="https://i.imgur.com/lk8k6L0.png" width=600 weigth=500 alt="Dystopia"></a>
  <br>
  Dragonet
  <br>
</h1>

<h4 align="center">Dragonet Command and Control</h4>

<p align="center">
    <img src="https://img.shields.io/badge/Backdoor_Platform-blue">
    <img src="https://img.shields.io/badge/Version-2.0.0-blue">
    <img src="https://img.shields.io/badge/Go-1.23.1-blue">
</p>

---

DragonetC2 is a sophisticated Discord-based Command and Control (C2) backdoor written in Go. This project demonstrates advanced remote access capabilities through a Discord bot interface, allowing for covert system control and information gathering.

**⚠️ DISCLAIMER: This project is for educational purposes only. The authors do not condone or support any malicious use of this software. Use responsibly and only on systems you own or have explicit permission to test.**

## Features

- Discord-based command and control
- Remote command execution
- File upload and download capabilities
- Screenshot capture
- System information gathering
- Persistence mechanisms
- Location tracking
- Process listing
- Directory navigation
- Wallpaper changing

## Commands

The bot responds to both text commands and slash commands:

### Text Commands
- `🏃‍♂️ <command>`: Runs a system command
- `📸`: Takes a screenshot of all displays
- `👇 <file>`: Uploads a specified file from the target system
- `☝️ <path>`: Downloads the attached file to the specified path on the target system
- `💀`: Shuts down the bot
- `!help`: Displays the help menu

### Slash Commands
- `/cmd <command>`: Runs a system command
- `/powershell <command>`: Runs a PowerShell command
- `/screenshot`: Takes a screenshot of all displays
- `/download <file>`: Downloads a specified file from the target system
- `/upload <url> <path>`: Uploads a file from a URL to a specified path on the target system
- `/location`: Retrieves the current IP location
- `/cd <path>`: Changes the working directory
- `/ls [path]`: Lists directory contents
- `/process`: Lists all running processes
- `/persistent`: Makes the agent persistent on the target machine
- `/creds`: Retrieve Chrome credentials on the target machine
- `/wallpaper <url>`: Changes the desktop wallpaper
- `/keylogger start`: Start a keylogger on the target machine
- `/keylogger stop`: Stop the keylogger on the target machine
- `/terminate`: Shuts down the bot
- `/shutdown`: Shuts down the bot
- `/help`: Displays the help menu

## Setup

1. Clone the repository
2. Install the required Go dependencies:

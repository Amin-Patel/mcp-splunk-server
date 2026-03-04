**Claude Desktop Configuration Guide**

**Connecting a Local MCP Server to Claude Desktop**

**Introduction**

Claude Desktop supports the **Model Context Protocol (MCP)**, which
allows Claude to connect to external tools and services. These tools run
through **MCP servers**, which Claude can start locally on the user\'s
machine.

In our project, we are building an MCP server (mcp_server.py) that
connects **Splunk logs with AI analysis**. For Claude Desktop to
communicate with this server, we must configure it using a configuration
file called claude_desktop_config.json.

This guide explains where the configuration file is located on Windows
and how to correctly configure it to connect a local Python MCP server.

**1. Location of claude_desktop_config.json on Windows**

Claude Desktop stores its configuration files inside the **Roaming
AppData directory**.

**Environment Variable Path**

%APPDATA%\\Claude\\claude_desktop_config.json

**Example Expanded Path**

On a Windows system, the full path typically looks like:

C:\\Users\\\<USERNAME\>\\AppData\\Roaming\\Claude\\claude_desktop_config.json

Example from our system:

C:\\Users\\amin9.AAZKA\\AppData\\Roaming\\Claude\\claude_desktop_config.json

**How to Access the Folder**

1.  Press **Windows + R**

2.  Type:

%APPDATA%

3.  Press **Enter**

4.  Open the folder named:

Claude

Inside this folder you can create or edit:

claude_desktop_config.json

Claude Desktop reads this file **every time the application starts** to
determine which MCP servers should be launched.

**2. JSON Configuration to Connect the MCP Server**

To connect our Python MCP server (mcp_server.py), we must define it
inside the configuration file using JSON.

Below is the required syntax.

{\
\"mcpServers\": {\
\"splunk-ai-server\": {\
\"command\": \"python\",\
\"args\": \[\
\"C:\\\\Users\\\\amin9.AAZKA\\\\SplunkAI\\\\mcp_server.py\"\
\]\
}\
}\
}

**3. Explanation of the Configuration Fields**

**mcpServers**

This object contains all MCP servers Claude Desktop should run.

Each entry represents a separate MCP server.

**\"splunk-ai-server\"**

This is the **name of the MCP server**.\
Claude Desktop will display this name in the MCP server list in its
developer settings.

**\"command\"**

The command used to start the server.

Since our server is written in Python, we use:

python

**\"args\"**

This field specifies the arguments passed to the command.

In this case, it contains the **path to the MCP server script**.

Claude Desktop will effectively run:

python C:\\Users\\amin9.AAZKA\\SplunkAI\\mcp_server.py

when the application starts.

**4. How Claude Desktop Uses the Configuration**

When Claude Desktop launches, it performs the following steps:

1.  Reads claude_desktop_config.json

2.  Finds all configured MCP servers

3.  Executes the specified command

4.  Starts the MCP server locally

5.  Loads all tools exposed by the server

This allows Claude to interact with external systems such as:

- Splunk logs

- Security monitoring tools

- Databases

- Custom APIs

**5. Project Architecture**

In our cybersecurity AI project, the architecture works as follows:

Splunk Logs\
│\
▼\
MCP Server (mcp_server.py)\
│\
▼\
Claude Desktop\
│\
▼\
AI Analysis and Security Insights

The MCP server acts as the **bridge between Splunk data and Claude\'s AI
capabilities**, enabling automated security analysis.

✅ This configuration allows Claude Desktop to automatically start the
MCP server and interact with tools exposed by it.

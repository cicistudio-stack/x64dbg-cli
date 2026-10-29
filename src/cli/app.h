#pragma once

namespace cli
{
// Entry point of the "GUI side" (called by _gui_guiinit on the main thread). Returns when the CLI is done.
int guiMain();
// Asks the CLI to shut down (GUI_CLOSE_APPLICATION, Ctrl+C, !quit, EOF).
void requestShutdown(const char* reason);
}

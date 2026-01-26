# WPP Remover - IDA Plugin for Removing WPP Calls

## Overview

WPP Remover is an IDA Pro plugin that removes Windows Performance Profiling (WPP) calls during decompilation, resulting in cleaner pseudocode for analysis.

## Features

- Removes WPP calls from Hex-Rays decompiler output
- Only activates for Windows PE files

## Installation

### Method 1: Using hcli (Recommended)

```
hcli plugin install wpp-remover
```

### Method 2: Manual Installation
Copy `wpp_remover.py` to your IDA plugins directory (`%IDADIR%\plugins` or `%APPDATA%\Hex-Rays\IDA Pro\plugins`)

## Usage

- Plugin activates automatically for Windows PE files
- Toggle on/off: Right-click in decompiled view → "Toggle WPP Remover"

![](https://raw.githubusercontent.com/L4ys/IDA-WPP-Remover/refs/heads/main/preview.gif)

## How it Works

It uses a Hex-Rays microcode optimization pass to find calls to `WPP_SF*` functions and replace them with NOPs before pseudocode generation.

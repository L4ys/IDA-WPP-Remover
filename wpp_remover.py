import ida_name
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_kernwin

class wpp_remover_optimizer_t(ida_hexrays.optblock_t):
    def func(self, blk):
        if self.handle_wpp_call(blk):
            return 1
        return 0

    def handle_wpp_call(self, blk):
        changed = False

        ins = blk.head
        while ins:
            if ins.opcode == ida_hexrays.m_call and ins.l.t == ida_hexrays.mop_v:
                name = ida_name.get_name(ins.l.g)
                if name.startswith("WPP_SF_"):
                    blk.make_nop(ins)
                    changed = True
            ins = ins.next

        return changed

class HexraysPopupHook(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        ida_kernwin.UI_Hooks.__init__(self)
        self.plugin = plugin

    def finish_populating_widget_popup(self, widget, popup, ctx):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(widget, popup, "wpp_remover:toggle", "WPP Remover")

# --------------------------------------------------------------------------
# a plugin interface, boilerplate code
class wpp_remover_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    wanted_name = "WPP Remover"
    wanted_hotkey = ""
    comment = "Remove WPP calls from hexrays decompiled code"
    help = ""

    def __init__(self):
        self.optimizer = None
        self.is_enabled = False
        self.ui_hook = None

    def register_context_menu(self):
        # Register the action
        action_desc = ida_kernwin.action_desc_t(
            "wpp_remover:toggle",
            "Toggle WPP Remover",
            self.toggle_handler(),
            None,
            "Enable/Disable WPP call removal",
            -1
        )
        ida_kernwin.register_action(action_desc)

        # Setup the UI hook
        self.ui_hook = HexraysPopupHook(self)
        self.ui_hook.hook()

    def toggle_handler(self):
        class ToggleActionHandler(ida_kernwin.action_handler_t):
            def __init__(self, plugin):
                ida_kernwin.action_handler_t.__init__(self)
                self.plugin = plugin

            def activate(self, ctx):
                if self.plugin.is_enabled:
                    self.plugin.disable_optimizer()
                else:
                    self.plugin.enable_optimizer()

                widget = ida_kernwin.get_current_widget()
                if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
                    vu = ida_hexrays.get_widget_vdui(widget)
                    if vu:
                        vu.refresh_view(True)
                return 1

            def update(self, ctx):
                # Always enable this menu item
                return ida_kernwin.AST_ENABLE_ALWAYS

        return ToggleActionHandler(self)

    def enable_optimizer(self):
        if not self.is_enabled:
            self.optimizer.install()
            self.is_enabled = True
            print("WPP Remover: Enabled")

    def disable_optimizer(self):
        if self.is_enabled:
            self.optimizer.remove()
            self.is_enabled = False
            print("WPP Remover: Disabled")

    def is_windows_file(self):
        # Check if current file is a Windows PE file
        return ida_ida.inf_get_filetype() == ida_ida.f_PE

    def init(self):
        # First, check if the file is a Windows PE file
        if not self.is_windows_file():
            return ida_idaapi.PLUGIN_SKIP

        if ida_hexrays.init_hexrays_plugin():
            self.optimizer = wpp_remover_optimizer_t()
            self.register_context_menu()
            print("WPP Remover plugin initialized")

            self.enable_optimizer()

            return ida_idaapi.PLUGIN_KEEP
        return ida_idaapi.PLUGIN_SKIP

    def term(self):
        # Unregister the action and unhook
        if self.ui_hook:
            self.ui_hook.unhook()
        ida_kernwin.unregister_action("wpp_remover:toggle")
        if self.optimizer and self.is_enabled:
            self.optimizer.remove()

    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return wpp_remover_plugin_t()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2014, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Wrapper for user32.dll in ctypes.
"""

__revision__ = "$Id: user32.py 1299 2013-12-20 09:30:55Z qvasimodo $"

from defines import *
from version import bits
from kernel32 import GetLastError, SetLastError
from gdi32 import POINT, PPOINT, LPPOINT, RECT, PRECT, LPRECT

#==============================================================================
# This is used later on to calculate the list of exported symbols.
_all = None
_all = set(vars().keys())
#==============================================================================

#--- Helpers ------------------------------------------------------------------

def MAKE_WPARAM(wParam):
    """
    Convert arguments to the WPARAM type.
    Used automatically by SendMessage, PostMessage, etc.
    You shouldn't need to call this function.
    """
    wParam = ctypes.cast(wParam, LPVOID).value
    if wParam is None:
        wParam = 0
    return wParam

def MAKE_LPARAM(lParam):
    """
    Convert arguments to the LPARAM type.
    Used automatically by SendMessage, PostMessage, etc.
    You shouldn't need to call this function.
    """
    return ctypes.cast(lParam, LPARAM)

class __WindowEnumerator (object):
    """
    Window enumerator class. Used internally by the window enumeration APIs.
    """
    def __init__(self):
        self.hwnd = list()
    def __call__(self, hwnd, lParam):
##        print hwnd  # XXX DEBUG
        self.hwnd.append(hwnd)
        return TRUE

#--- Types --------------------------------------------------------------------

WNDENUMPROC = WINFUNCTYPE(BOOL, HWND, PVOID)

#--- Constants ----------------------------------------------------------------

HWND_DESKTOP    = 0
HWND_TOP        = 1
HWND_BOTTOM     = 1
HWND_TOPMOST    = -1
HWND_NOTOPMOST  = -2
HWND_MESSAGE    = -3

# GetWindowLong / SetWindowLong
GWL_WNDPROC                          = -4
GWL_HINSTANCE                        = -6
GWL_HWNDPARENT                       = -8
GWL_ID                               = -12
GWL_STYLE                            = -16
GWL_EXSTYLE                          = -20
GWL_USERDATA                         = -21

# GetWindowLongPtr / SetWindowLongPtr
GWLP_WNDPROC                         = GWL_WNDPROC
GWLP_HINSTANCE                       = GWL_HINSTANCE
GWLP_HWNDPARENT                      = GWL_HWNDPARENT
GWLP_STYLE                           = GWL_STYLE
GWLP_EXSTYLE                         = GWL_EXSTYLE
GWLP_USERDATA                        = GWL_USERDATA
GWLP_ID                              = GWL_ID

# ShowWindow
SW_HIDE                             = 0
SW_SHOWNORMAL                       = 1
SW_NORMAL                           = 1
SW_SHOWMINIMIZED                    = 2
SW_SHOWMAXIMIZED                    = 3
SW_MAXIMIZE                         = 3
SW_SHOWNOACTIVATE                   = 4
SW_SHOW                             = 5
SW_MINIMIZE                         = 6
SW_SHOWMINNOACTIVE                  = 7
SW_SHOWNA                           = 8
SW_RESTORE                          = 9
SW_SHOWDEFAULT                      = 10
SW_FORCEMINIMIZE                    = 11

# SendMessageTimeout flags
SMTO_NORMAL                         = 0
SMTO_BLOCK                          = 1
SMTO_ABORTIFHUNG                    = 2
SMTO_NOTIMEOUTIFNOTHUNG 			= 8
SMTO_ERRORONEXIT                    = 0x20

# WINDOWPLACEMENT flags
WPF_SETMINPOSITION                  = 1
WPF_RESTORETOMAXIMIZED              = 2
WPF_ASYNCWINDOWPLACEMENT            = 4

# GetAncestor flags
GA_PARENT                           = 1
GA_ROOT                             = 2
GA_ROOTOWNER                        = 3

# GetWindow flags
GW_HWNDFIRST                        = 0
GW_HWNDLAST                         = 1
GW_HWNDNEXT                         = 2
GW_HWNDPREV                         = 3
GW_OWNER                            = 4
GW_CHILD                            = 5
GW_ENABLEDPOPUP                     = 6

#--- Window messages ----------------------------------------------------------

WM_USER                              = 0x400
WM_APP                               = 0x800

WM_NULL                              = 0
WM_CREATE                            = 1
WM_DESTROY                           = 2
WM_MOVE                              = 3
WM_SIZE                              = 5
WM_ACTIVATE                          = 6
WA_INACTIVE                          = 0
WA_ACTIVE                            = 1
WA_CLICKACTIVE                       = 2
WM_SETFOCUS                          = 7
WM_KILLFOCUS                         = 8
WM_ENABLE                            = 0x0A
WM_SETREDRAW                         = 0x0B
WM_SETTEXT                           = 0x0C
WM_GETTEXT                           = 0x0D
WM_GETTEXTLENGTH                     = 0x0E
WM_PAINT                             = 0x0F
WM_CLOSE                             = 0x10
WM_QUERYENDSESSION                   = 0x11
WM_QUIT                              = 0x12
WM_QUERYOPEN                         = 0x13
WM_ERASEBKGND                        = 0x14
WM_SYSCOLORCHANGE                    = 0x15
WM_ENDSESSION                        = 0x16
WM_SHOWWINDOW                        = 0x18
WM_WININICHANGE                      = 0x1A
WM_SETTINGCHANGE                	 = WM_WININICHANGE
WM_DEVMODECHANGE                     = 0x1B
WM_ACTIVATEAPP                       = 0x1C
WM_FONTCHANGE                        = 0x1D
WM_TIMECHANGE                        = 0x1E
WM_CANCELMODE                        = 0x1F
WM_SETCURSOR                         = 0x20
WM_MOUSEACTIVATE                     = 0x21
WM_CHILDACTIVATE                     = 0x22
WM_QUEUESYNC                         = 0x23
WM_GETMINMAXINFO                     = 0x24
WM_PAINTICON                         = 0x26
WM_ICONERASEBKGND                    = 0x27
WM_NEXTDLGCTL                        = 0x28
WM_SPOOLERSTATUS                     = 0x2A
WM_DRAWITEM                          = 0x2B
WM_MEASUREITEM                       = 0x2C
WM_DELETEITEM                        = 0x2D
WM_VKEYTOITEM                        = 0x2E
WM_CHARTOITEM                        = 0x2F
WM_SETFONT                           = 0x30
WM_GETFONT                           = 0x31
WM_SETHOTKEY                         = 0x32
WM_GETHOTKEY                         = 0x33
WM_QUERYDRAGICON                     = 0x37
WM_COMPAREITEM                       = 0x39
WM_GETOBJECT                    	 = 0x3D
WM_COMPACTING                        = 0x41
WM_OTHERWINDOWCREATED                = 0x42
WM_OTHERWINDOWDESTROYED              = 0x43
WM_COMMNOTIFY                        = 0x44

CN_RECEIVE                           = 0x1
CN_TRANSMIT                          = 0x2
CN_EVENT                             = 0x4

WM_WINDOWPOSCHANGING                 = 0x46
WM_WINDOWPOSCHANGED                  = 0x47
WM_POWER                             = 0x48

PWR_OK                               = 1
PWR_FAIL                             = -1
PWR_SUSPENDREQUEST                   = 1
PWR_SUSPENDRESUME                    = 2
PWR_CRITICALRESUME                   = 3

WM_COPYDATA                          = 0x4A
WM_CANCELJOURNAL                     = 0x4B
WM_NOTIFY                            = 0x4E
WM_INPUTLANGCHANGEREQUEST            = 0x50
WM_INPUTLANGCHANGE                   = 0x51
WM_TCARD                             = 0x52
WM_HELP                              = 0x53
WM_USERCHANGED                       = 0x54
WM_NOTIFYFORMAT                      = 0x55
WM_CONTEXTMENU                       = 0x7B
WM_STYLECHANGING                     = 0x7C
WM_STYLECHANGED                      = 0x7D
WM_DISPLAYCHANGE                     = 0x7E
WM_GETICON                           = 0x7F
WM_SETICON                           = 0x80
WM_NCCREATE                          = 0x81
WM_NCDESTROY                         = 0x82
WM_NCCALCSIZE                        = 0x83
WM_NCHITTEST                         = 0x84
WM_NCPAINT                           = 0x85
WM_NCACTIVATE                        = 0x86
WM_GETDLGCODE                        = 0x87
WM_SYNCPAINT                    	 = 0x88
WM_NCMOUSEMOVE                       = 0x0A0
WM_NCLBUTTONDOWN                     = 0x0A1
WM_NCLBUTTONUP                       = 0x0A2
WM_NCLBUTTONDBLCLK                   = 0x0A3
WM_NCRBUTTONDOWN                     = 0x0A4
WM_NCRBUTTONUP                       = 0x0A5
WM_NCRBUTTONDBLCLK                   = 0x0A6
WM_NCMBUTTONDOWN                     = 0x0A7
WM_NCMBUTTONUP                       = 0x0A8
WM_NCMBUTTONDBLCLK                   = 0x0A9
WM_KEYFIRST                          = 0x100
WM_KEYDOWN                           = 0x100
WM_KEYUP                             = 0x101
WM_CHAR                              = 0x102
WM_DEADCHAR                          = 0x103
WM_SYSKEYDOWN                        = 0x104
WM_SYSKEYUP                          = 0x105
WM_SYSCHAR                           = 0x106
WM_SYSDEADCHAR                       = 0x107
WM_KEYLAST                           = 0x108
WM_INITDIALOG                        = 0x110
WM_COMMAND                           = 0x111
WM_SYSCOMMAND                        = 0x112
WM_TIMER                             = 0x113
WM_HSCROLL                           = 0x114
WM_VSCROLL                           = 0x115
WM_INITMENU                          = 0x116
WM_INITMENUPOPUP                     = 0x117
WM_MENUSELECT                        = 0x11F
WM_MENUCHAR                          = 0x120
WM_ENTERIDLE                         = 0x121
WM_CTLCOLORMSGBOX                    = 0x132
WM_CTLCOLOREDIT                      = 0x133
WM_CTLCOLORLISTBOX                   = 0x134
WM_CTLCOLORBTN                       = 0x135
WM_CTLCOLORDLG                       = 0x136
WM_CTLCOLORSCROLLBAR                 = 0x137
WM_CTLCOLORSTATIC                    = 0x138
WM_MOUSEFIRST                        = 0x200
WM_MOUSEMOVE                         = 0x200
WM_LBUTTONDOWN                       = 0x201
WM_LBUTTONUP                         = 0x202
WM_LBUTTONDBLCLK                     = 0x203
WM_RBUTTONDOWN                       = 0x204
WM_RBUTTONUP                         = 0x205
WM_RBUTTONDBLCLK                     = 0x206
WM_MBUTTONDOWN                       = 0x207
WM_MBUTTONUP                         = 0x208
WM_MBUTTONDBLCLK                     = 0x209
WM_MOUSELAST                         = 0x209
WM_PARENTNOTIFY                      = 0x210
WM_ENTERMENULOOP                     = 0x211
WM_EXITMENULOOP                      = 0x212
WM_MDICREATE                         = 0x220
WM_MDIDESTROY                        = 0x221
WM_MDIACTIVATE                       = 0x222
WM_MDIRESTORE                        = 0x223
WM_MDINEXT                           = 0x224
WM_MDIMAXIMIZE                       = 0x225
WM_MDITILE                           = 0x226
WM_MDICASCADE                        = 0x227
WM_MDIICONARRANGE                    = 0x228
WM_MDIGETACTIVE                      = 0x229
WM_MDISETMENU                        = 0x230
WM_DROPFILES                         = 0x233
WM_MDIREFRESHMENU                    = 0x234
WM_CUT                               = 0x300
WM_COPY                              = 0x301
WM_PASTE                             = 0x302
WM_CLEAR                             = 0x303
WM_UNDO                              = 0x304
WM_RENDERFORMAT                      = 0x305
WM_RENDERALLFORMATS                  = 0x306
WM_DESTROYCLIPBOARD                  = 0x307
WM_DRAWCLIPBOARD                     = 0x308
WM_PAINTCLIPBOARD                    = 0x309
WM_VSCROLLCLIPBOARD                  = 0x30A
WM_SIZECLIPBOARD                     = 0x30B
WM_ASKCBFORMATNAME                   = 0x30C
WM_CHANGECBCHAIN                     = 0x30D
WM_HSCROLLCLIPBOARD                  = 0x30E
WM_QUERYNEWPALETTE                   = 0x30F
WM_PALETTEISCHANGING                 = 0x310
WM_PALETTECHANGED                    = 0x311
WM_HOTKEY                            = 0x312
WM_PRINT                        	 = 0x317
WM_PRINTCLIENT                       = 0x318
WM_PENWINFIRST                       = 0x380
WM_PENWINLAST                        = 0x38F

#--- Structures ---------------------------------------------------------------

# typedef struct _WINDOWPLACEMENT {
#     UINT length;
#     UINT flags;
#     UINT showCmd;
#     POINT ptMinPosition;
#     POINT ptMaxPosition;
#     RECT rcNormalPosition;
# } WINDOWPLACEMENT;
class WINDOWPLACEMENT(Structure):
    _fields_ = [
        ('length',              UINT),
        ('flags',               UINT),
        ('showCmd',             UINT),
        ('ptMinPosition',       POINT),
        ('ptMaxPosition',       POINT),
        ('rcNormalPosition',    RECT),
    ]
PWINDOWPLACEMENT  = POINTER(WINDOWPLACEMENT)
LPWINDOWPLACEMENT = PWINDOWPLACEMENT

# typedef struct tagGUITHREADINFO {
#     DWORD cbSize;
#     DWORD flags;
#     HWND hwndActive;
#     HWND hwndFocus;
#     HWND hwndCapture;
#     HWND hwndMenuOwner;
#     HWND hwndMoveSize;
#     HWND hwndCaret;
#     RECT rcCaret;
# } GUITHREADINFO, *PGUITHREADINFO;
class GUITHREADINFO(Structure):
    _fields_ = [
        ('cbSize',          DWORD),
        ('flags',           DWORD),
        ('hwndActive',      HWND),
        ('hwndFocus',       HWND),
        ('hwndCapture',     HWND),
        ('hwndMenuOwner',   HWND),
        ('hwndMoveSize',    HWND),
        ('hwndCaret',       HWND),
        ('rcCaret',         RECT),
    ]
PGUITHREADINFO  = POINTER(GUITHREADINFO)
LPGUITHREADINFO = PGUITHREADINFO

#--- High level classes -------------------------------------------------------

# Point() and Rect() are here instead of gdi32.py because they were mainly
# created to handle window coordinates rather than drawing on the screen.

# XXX not sure if these classes should be psyco-optimized,
# it may not work if the user wants to serialize them for some reason

class Point(object):
    """
    Python wrapper over the L{POINT} class.

    @type x: int
    @ivar x: Horizontal coordinate
    @type y: int
    @ivar y: Vertical coordinate
    """

    def __init__(self, x = 0, y = 0):
        """
        @see: L{POINT}
        @type  x: int
        @param x: Horizontal coordinate
        @type  y: int
        @param y: Vertical coordinate
        """
        self.x = x
        self.y = y

    def __iter__(self):
        return (self.x, self.y).__iter__()

    def __len__(self):
        return 2

    def __getitem__(self, index):
        return (self.x, self.y) [index]

    def __setitem__(self, index, value):
        if   index == 0:
            self.x = value
        elif index == 1:
            self.y = value
        else:
            raise IndexError("index out of range")

    @property
    def _as_parameter_(self):
        """
        Compatibility with ctypes.
        Allows passing transparently a Point object to an API call.
        """
        return POINT(self.x, self.y)

    def screen_to_client(self, hWnd):
        """
        Translates window screen coordinates to client coordinates.

        @see: L{client_to_screen}, L{translate}

        @type  hWnd: int or L{HWND} or L{system.Window}
        @param hWnd: Window handle.

        @rtype:  L{Point}
        @return: New object containing the translated coordinates.
        """
        return ScreenToClient(hWnd, self)

    def client_to_screen(self, hWnd):
        """
        Translates window client coordinates to screen coordinates.

        @see: L{screen_to_client}, L{translate}

        @type  hWnd: int or L{HWND} or L{system.Window}
        @param hWnd: Window handle.

        @rtype:  L{Point}
        @return: New object containing the translated coordinates.
        """
        return ClientToScreen(hWnd, self)

    def translate(self, hWndFrom = HWND_DESKTOP, hWndTo = HWND_DESKTOP):
        """
        Translate coordinates from one window to another.

        @note: To translate multiple points it's more efficient to use the
            L{MapWindowPoints} function instead.

        @see: L{client_to_screen}, L{screen_to_client}

        @type  hWndFrom: int or L{HWND} or L{system.Window}
        @param hWndFrom: Window handle to translate from.
            Use C{HWND_DESKTOP} for screen coordinates.

        @type  hWndTo: int or L{HWND} or L{system.Window}
        @param hWndTo: Window handle to translate to.
            Use C{HWND_DESKTOP} for screen coordinates.

        @rtype:  L{Point}
        @return: New object containing the translated coordinates.
        """
        return MapWindowPoints(hWndFrom, hWndTo, [self])

class Rect(object):
    """
    Python wrapper over the L{RECT} class.

    @type   left: int
    @ivar   left: Horizontal coordinate for the top left corner.
    @type    top: int
    @ivar    top: Vertical coordinate for the top left corner.
    @type  right: int
    @ivar  right: Horizontal coordinate for the bottom right corner.
    @type bottom: int
    @ivar bottom: Vertical coordinate for the bottom right corner.

    @type  width: int
    @ivar  width: Width in pixels. Same as C{right - left}.
    @type height: int
    @ivar height: Height in pixels. Same as C{bottom - top}.
    """

    def __init__(self, left = 0, top = 0, right = 0, bottom = 0):
        """
        @see: L{RECT}
        @type    left: int
        @param   left: Horizontal coordinate for the top left corner.
        @type     top: int
        @param    top: Vertical coordinate for the top left corner.
        @type   right: int
        @param  right: Horizontal coordinate for the bottom right corner.
        @type  bottom: int
        @param bottom: Vertical coordinate for the bottom right corner.
        """
        self.left   = left
        self.top    = top
        self.right  = right
        self.bottom = bottom

    def __iter__(self):
        return (self.left, self.top, self.right, self.bottom).__iter__()

    def __len__(self):
        return 2

    def __getitem__(self, index):
        return (self.left, self.top, self.right, self.bottom) [index]

    def __setitem__(self, index, value):
        if   index == 0:
            self.left   = value
        elif index == 1:
            self.top    = value
        elif index == 2:
            self.right  = value
        elif index == 3:
            self.bottom = value
        else:
            raise IndexError, "index out of range"

    @property
    def _as_parameter_(self):
        """
        Compatibility with ctypes.
        Allows passing transparently a Point object to an API call.
        """
        return RECT(self.left, self.top, self.right, self.bottom)

    def __get_width(self):
        return self.right - self.left

    def __get_height(self):
        return self.bottom - self.top

    def __set_width(self, value):
        self.right = value - self.left

    def __set_height(self, value):
        self.bottom = value - self.top

    width  = property(__get_width, __set_width)
    height = property(__get_height, __set_height)

    def screen_to_client(self, hWnd):
        """
        Translates window screen coordinates to client coordinates.

        @see: L{client_to_screen}, L{translate}

        @type  hWnd: int or L{HWND} or L{system.Window}
        @param hWnd: Window handle.

        @rtype:  L{Rect}
        @return: New object containing the translated coordinates.
        """
        topleft     = ScreenToClient(hWnd, (self.left,   self.top))
        bottomright = ScreenToClient(hWnd, (self.bottom, self.right))
        return Rect( topleft.x, topleft.y, bottomright.x, bottomright.y )

    def client_to_screen(self, hWnd):
        """
        Translates window client coordinates to screen coordinates.

        @see: L{screen_to_client}, L{translate}

        @type  hWnd: int or L{HWND} or L{system.Window}
        @param hWnd: Window handle.

        @rtype:  L{Rect}
        @return: New object containing the translated coordinates.
        """
        topleft     = ClientToScreen(hWnd, (self.left,   self.top))
        bottomright = ClientToScreen(hWnd, (self.bottom, self.right))
        return Rect( topleft.x, topleft.y, bottomright.x, bottomright.y )

    def translate(self, hWndFrom = HWND_DESKTOP, hWndTo = HWND_DESKTOP):
        """
        Translate coordinates from one window to another.

        @see: L{client_to_screen}, L{screen_to_client}

        @type  hWndFrom: int or L{HWND} or L{system.Window}
        @param hWndFrom: Window handle to translate from.
            Use C{HWND_DESKTOP} for screen coordinates.

        @type  hWndTo: int or L{HWND} or L{system.Window}
        @param hWndTo: Window handle to translate to.
            Use C{HWND_DESKTOP} for screen coordinates.

        @rtype:  L{Rect}
        @return: New object containing the translated coordinates.
        """
        points = [ (self.left, self.top), (self.right, self.bottom) ]
        return MapWindowPoints(hWndFrom, hWndTo, points)

class WindowPlacement(object):
    """
    Python wrapper over the L{WINDOWPLACEMENT} class.
    """

    def __init__(self, wp = None):
        """
        @type  wp: L{WindowPlacement} or L{WINDOWPLACEMENT}
        @param wp: Another window placement object.
        """

        # Initialize all properties with empty values.
        self.flags            = 0
        self.showCmd          = 0
        self.ptMinPosition    = Point()
        self.ptMaxPosition    = Point()
        self.rcNormalPosition = Rect()

        # If a window placement was given copy it's properties.
        if wp:
            self.flags            = wp.flags
            self.showCmd          = wp.showCmd
            self.ptMinPosition    = Point( wp.ptMinPosition.x, wp.ptMinPosition.y )
            self.ptMaxPosition    = Point( wp.ptMaxPosition.x, wp.ptMaxPosition.y )
            self.rcNormalPosition = Rect(
                                        wp.rcNormalPosition.left,
                                        wp.rcNormalPosition.top,
                                        wp.rcNormalPosition.right,
                                        wp.rcNormalPosition.bottom,
                                        )

    @property
    def _as_parameter_(self):
        """
        Compatibility with ctypes.
        Allows passing transparently a Point object to an API call.
        """
        wp                          = WINDOWPLACEMENT()
        wp.length                   = sizeof(wp)
        wp.flags                    = self.flags
        wp.showCmd                  = self.showCmd
        wp.ptMinPosition.x          = self.ptMinPosition.x
        wp.ptMinPosition.y          = self.ptMinPosition.y
        wp.ptMaxPosition.x          = self.ptMaxPosition.x
        wp.ptMaxPosition.y          = self.ptMaxPosition.y
        wp.rcNormalPosition.left    = self.rcNormalPosition.left
        wp.rcNormalPosition.top     = self.rcNormalPosition.top
        wp.rcNormalPosition.right   = self.rcNormalPosition.right
        wp.rcNormalPosition.bottom  = self.rcNormalPosition.bottom
        return wp


#==============================================================================
# This calculates the list of exported symbols.
_all = set(vars().keys()).difference(_all)
__all__ = [_x for _x in _all if not _x.startswith('_')]
__all__.sort()
#==============================================================================

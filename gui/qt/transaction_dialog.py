#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import copy
import datetime
import json

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electroncash.address import Address, PublicKey, ScriptOutput
from electroncash.bitcoin import base_encode
from electroncash.i18n import _
from electroncash.plugins import run_hook
from electroncash import web

from electroncash.util import bfh, Weak, PrintError
from .util import *

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

if sys.platform.lower().startswith('win'):
    # NB: on Qt for Windows the 'ⓢ' symbol looks aliased and bad. So we do this
    # for windows.
    SCHNORR_SIGIL = "(S)"
else:
    # On Linux & macOS it looks fine so we go with the more fancy unicode
    SCHNORR_SIGIL = "ⓢ"

def show_transaction(tx, parent, desc=None, prompt_if_unsaved=False):
    d = TxDialog(tx, parent, desc, prompt_if_unsaved)
    dialogs.append(d)
    d.show()
    return d

class TxDialog(QDialog, MessageBoxMixin, PrintError):

    throttled_update_sig = pyqtSignal()  # connected to self.throttled_update -- emit from thread to do update in main thread
    dl_done_sig = pyqtSignal()  # connected to an inner function to get a callback in main thread upon dl completion

    def __init__(self, tx, parent, desc, prompt_if_unsaved):
        '''Transactions in the wallet will show their description.
        Pass desc to give a description for txs not yet in the wallet.
        '''
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)
        # Take a copy; it might get updated in the main window by
        # e.g. the FX plugin.  If this happens during or after a long
        # sign operation the signatures are lost.
        self.tx = copy.deepcopy(tx)
        self.tx.deserialize()
        self.main_window = parent
        self.wallet = parent.wallet
        self.prompt_if_unsaved = prompt_if_unsaved
        self.saved = False
        self.desc = desc
        self.cashaddr_signal_slots = []
        self._dl_pct = None
        self._closed = False
        self.tx_height = None

        self.setMinimumWidth(750)
        self.setWindowTitle(_("Transaction"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e  = ButtonsLineEdit()
        self.tx_hash_e.addCopyButton()
        weakSelfRef = Weak.ref(self)
        qr_show = lambda: weakSelfRef() and weakSelfRef().main_window.show_qrcode(str(weakSelfRef().tx_hash_e.text()), 'Transaction ID', parent=weakSelfRef())
        icon = ":icons/qrcode_white.svg" if ColorScheme.dark_scheme else ":icons/qrcode.svg"
        self.tx_hash_e.addButton(icon, qr_show, _("Show as QR code"))
        self.tx_hash_e.setReadOnly(True)
        vbox.addWidget(self.tx_hash_e)
        self.tx_desc = QLabel()
        vbox.addWidget(self.tx_desc)
        self.status_label = QLabel()
        vbox.addWidget(self.status_label)
        self.date_label = QLabel()
        vbox.addWidget(self.date_label)
        self.amount_label = QLabel()
        vbox.addWidget(self.amount_label)
        self.size_label = QLabel()
        vbox.addWidget(self.size_label)
        self.fee_label = QLabel()
        vbox.addWidget(self.fee_label)

        for l in (self.tx_desc, self.status_label, self.date_label, self.amount_label, self.size_label, self.fee_label):
            # make these labels selectable by mouse in case user wants to copy-paste things in tx dialog
            l.setTextInteractionFlags(l.textInteractionFlags() | Qt.TextSelectableByMouse)

        def open_be_url(link):
            if link:
                try:
                    kind, thing = link.split(':')
                    url = web.BE_URL(self.main_window.config, kind, thing)
                except:
                    url = None
                if url:
                    webopen( url )
                else:
                    self.show_error(_('Unable to open in block explorer. Please be sure your block explorer is configured correctly in preferences.'))

        self.status_label.linkActivated.connect(open_be_url)

        self.add_io(vbox)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.do_broadcast)

        self.save_button = b = QPushButton(_("Save"))
        b.clicked.connect(self.save)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.qr_button = b = QPushButton()
        b.setIcon(QIcon(icon))
        b.clicked.connect(self.show_qr)

        self.copy_button = CopyButton(lambda: str(weakSelfRef() and weakSelfRef().tx),
                                      callback=lambda: weakSelfRef() and weakSelfRef().show_message(_("Transaction raw hex copied to clipboard.")))

        # Action buttons
        self.buttons = [self.sign_button, self.broadcast_button, self.cancel_button]
        # Transaction sharing buttons
        self.sharing_buttons = [self.copy_button, self.qr_button, self.save_button]

        run_hook('transaction_dialog', self)

        hbox = QHBoxLayout()
        hbox.addLayout(Buttons(*self.sharing_buttons))
        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        vbox.addLayout(hbox)

        self.throttled_update_sig.connect(self.throttled_update, Qt.QueuedConnection)
        self.initiate_fetch_input_data(True)

        self.update()

        # connect slots so we update in realtime as blocks come in, etc
        parent.history_updated_signal.connect(self.update_tx_if_in_wallet)
        parent.labels_updated_signal.connect(self.update_tx_if_in_wallet)
        parent.network_signal.connect(self.got_verified_tx)

    def initiate_fetch_input_data(self, force):
        weakSelfRef = Weak.ref(self)
        def dl_prog(pct):
            slf = weakSelfRef()
            if slf:
                slf._dl_pct = pct
                slf.throttled_update_sig.emit()
        def dl_done():
            slf = weakSelfRef()
            if slf:
                slf._dl_pct = None
                slf.throttled_update_sig.emit()
                slf.dl_done_sig.emit()
        dl_retries = 0
        def dl_done_mainthread():
            nonlocal dl_retries
            slf = weakSelfRef()
            if slf:
                if slf._closed:
                    return
                dl_retries += 1
                fee = slf.try_calculate_fee()
                if fee is None and dl_retries < 2:
                    if not self.is_fetch_input_data():
                        slf.print_error("input fetch incomplete; network use is disabled in GUI")
                        return
                    # retry at most once -- in case a slow server scrwed us up
                    slf.print_error("input fetch appears incomplete; retrying download once ...")
                    slf.tx.fetch_input_data(self.wallet, done_callback=dl_done, prog_callback=dl_prog, force=True, use_network=self.is_fetch_input_data())  # in this case we reallly do force
                elif fee is not None:
                    slf.print_error("input fetch success")
                else:
                    slf.print_error("input fetch failed")
        try: self.dl_done_sig.disconnect()  # disconnect previous
        except TypeError: pass
        self.dl_done_sig.connect(dl_done_mainthread, Qt.QueuedConnection)
        self.tx.fetch_input_data(self.wallet, done_callback=dl_done, prog_callback=dl_prog, force=force, use_network=self.is_fetch_input_data())



    def got_verified_tx(self, event, args):
        if event == 'verified' and args[0] == self.tx.txid():
            self.update()

    def update_tx_if_in_wallet(self):
        if self.tx.txid() in self.wallet.transactions:
            self.update()

    def do_broadcast(self):
        self.main_window.push_top_level_window(self)
        try:
            self.main_window.broadcast_transaction(self.tx, self.desc)
        finally:
            self.main_window.pop_top_level_window(self)
        self.saved = True
        self.update()

    def closeEvent(self, event):
        if (self.prompt_if_unsaved and not self.saved
            and not self.question(_('This transaction is not saved. Close anyway?'), title=_("Warning"))):
            event.ignore()
        else:
            event.accept()
            self._closed = True
            self.tx.fetch_cancel()
            parent = self.main_window
            if parent:
                # clean up connections so window gets gc'd
                try: parent.history_updated_signal.disconnect(self.update_tx_if_in_wallet)
                except TypeError: pass
                try: parent.network_signal.disconnect(self.got_verified_tx)
                except TypeError: pass
                try: parent.labels_updated_signal.disconnect(self.update_tx_if_in_wallet)
                except TypeError: pass
                for slot in self.cashaddr_signal_slots:
                    try: parent.gui_object.cashaddr_toggled_signal.disconnect(slot)
                    except TypeError: pass
                self.cashaddr_signal_slots = []

            __class__._pyqt_bug_gc_workaround = self  # <--- keep this object alive in PyQt until at least after this event handler completes. This is because on some platforms Python deletes the C++ object right away inside this event handler (QObject with no parent) -- which crashes Qt!
            def clr_workaround():
                __class__._pyqt_bug_gc_workaround = None
            QTimer.singleShot(0, clr_workaround)

            try:
                dialogs.remove(self)
            except ValueError:  # wasn't in list
                pass
            while True:
                try:
                    # Esoteric bug happens when user rejects password dialog on top of this window.. so we must keep popping self off the top_level_windows
                    self.main_window.pop_top_level_window(self)
                except ValueError:
                    break
            # The below is used to clean up any modal dialogs this txdialog may have up
            tlw = self.top_level_window()
            while tlw is not self:
                tlw.reject()
                tlw = self.top_level_window()

    def reject(self):
        # Override escape-key to close normally (and invoke closeEvent)
        self.close()

    def show_qr(self):
        text = bfh(str(self.tx))
        text = base_encode(text, base=43)
        try:
            self.main_window.show_qrcode(text, 'Transaction', parent=self)
        except Exception as e:
            self.show_message(str(e))

    def sign(self):
        def cleanup():
            self.main_window.pop_top_level_window(self)

        def sign_done(success):
            if success:
                self.sign_button.setDisabled(True)
                self.prompt_if_unsaved = True
                self.saved = False
            self.update()
            cleanup()

        self.main_window.push_top_level_window(self)
        self.main_window.sign_tx(self.tx, sign_done, on_pw_cancel=cleanup)

    def save(self):
        name = 'signed_%s.txn' % (self.tx.txid()[0:8]) if self.tx.is_complete() else 'unsigned.txn'
        fileName = self.main_window.getSaveFileName(_("Select where to save your signed transaction"), name, "*.txn")
        if fileName:
            tx_dict = self.tx.as_dict()
            with open(fileName, "w+", encoding='utf-8') as f:
                f.write(json.dumps(tx_dict, indent=4) + '\n')
            self.show_message(_("Transaction saved successfully"))
            self.saved = True

    @rate_limited(0.5, ts_after=True)
    def throttled_update(self):
        if not self._closed:
            self.update()

    def try_calculate_fee(self):
        ''' Try and compute fee by summing all the input values and subtracting
        the output values. We don't always have 'value' in all the inputs,
        so in that case None will be returned. '''
        fee = None
        try:
            fee = self.tx.get_fee()
        except (KeyError, TypeError, ValueError):
            # 'value' key missing or bad from an input
            pass
        return fee

    def update(self):
        desc = self.desc
        base_unit = self.main_window.base_unit()
        format_amount = self.main_window.format_amount
        tx_hash, status, label, can_broadcast, amount, fee, height, conf, timestamp, exp_n = self.wallet.get_tx_info(self.tx)
        self.tx_height = height
        desc = label or desc
        size = self.tx.estimated_size()
        self.broadcast_button.setEnabled(can_broadcast)
        can_sign = not self.tx.is_complete() and \
            (self.wallet.can_sign(self.tx) or bool(self.main_window.tx_external_keypairs))
        self.sign_button.setEnabled(can_sign)
        self.tx_hash_e.setText(tx_hash or _('Unknown'))
        if fee is None:
            fee = self.try_calculate_fee()
        if desc is None:
            self.tx_desc.hide()
        else:
            self.tx_desc.setText(_("Description") + ': ' + desc)
            self.tx_desc.show()

        if self.tx_height and tx_hash:
            status_extra = '&nbsp;&nbsp;( ' + _("Mined in block") + f': <a href="tx:{tx_hash}">{self.tx_height}</a>' + ' )'
        else:
            status_extra = ''

        self.status_label.setText(_('Status:') + ' ' + status + status_extra)

        if timestamp:
            time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
            self.date_label.setText(_("Date: {}").format(time_str))
            self.date_label.show()
        elif exp_n:
            text = '%d blocks'%(exp_n) if exp_n > 0 else _('unknown (low fee)')
            self.date_label.setText(_('Expected confirmation time') + ': ' + text)
            self.date_label.show()
        else:
            self.date_label.hide()
        if amount is None:
            amount_str = _("Transaction unrelated to your wallet")
        elif amount > 0:
            amount_str = _("Amount received:") + ' %s'% format_amount(amount) + ' ' + base_unit
        else:
            amount_str = _("Amount sent:") + ' %s'% format_amount(-amount) + ' ' + base_unit
        size_str = _("Size:") + ' %d bytes'% size
        fee_str = _("Fee") + ": "
        if fee is not None:
            fee_str += format_amount(fee) + ' ' + base_unit
            fee_str += '  ( %s ) '%  self.main_window.format_fee_rate(fee/size*1000)
            dusty_fee = self.tx.ephemeral.get('dust_to_fee', 0)
            if dusty_fee:
                fee_str += ' <font color=#999999>' + (_("( %s in dust was added to fee )") % format_amount(dusty_fee)) + '</font>'
        elif self._dl_pct is not None:
            fee_str = _('Downloading input data, please wait...') + ' {:.0f}%'.format(self._dl_pct)
        else:
            fee_str += _("unknown")
        self.amount_label.setText(amount_str)
        self.fee_label.setText(fee_str)
        self.size_label.setText(size_str)
        self.update_io()
        run_hook('transaction_dialog_update', self)

    def is_fetch_input_data(self):
        return bool(self.wallet.network and self.main_window.config.get('fetch_input_data', False))

    def set_fetch_input_data(self, b):
        self.main_window.config.set_key('fetch_input_data', bool(b))
        if self.is_fetch_input_data():
            self.initiate_fetch_input_data(bool(self.try_calculate_fee() is None))
        else:
            self.tx.fetch_cancel()
            self._dl_pct = None  # makes the "download progress" thing clear
            self.update()

    def add_io(self, vbox):
        if self.tx.locktime > 0:
            vbox.addWidget(QLabel("LockTime: %d\n" % self.tx.locktime))

        hbox = QHBoxLayout()
        hbox.setContentsMargins(0,0,0,0)

        hbox.addWidget(QLabel(_("Inputs") + ' (%d)'%len(self.tx.inputs())))


        hbox.addSpacerItem(QSpacerItem(20, 0))  # 20 px padding
        self.dl_input_chk = chk = QCheckBox(_("Download input data"))
        chk.setChecked(self.is_fetch_input_data())
        chk.clicked.connect(self.set_fetch_input_data)
        hbox.addWidget(chk)
        hbox.addStretch(1)
        if not self.wallet.network:
            # it makes no sense to enable this checkbox if the network is offline
            chk.setHidden(True)

        self.schnorr_label = QLabel(_('{} = Schnorr signed').format(SCHNORR_SIGIL))
        self.schnorr_label.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        f = self.schnorr_label.font()
        f.setPointSize(f.pointSize()-1)  # make it a little smaller
        self.schnorr_label.setFont(f)
        hbox.addWidget(self.schnorr_label)
        self.schnorr_label.setHidden(True)

        vbox.addLayout(hbox)

        self.i_text = i_text = QTextBrowser()
        i_text.setOpenLinks(False)  # disable automatic link opening
        i_text.anchorClicked.connect(self._open_internal_link)  # send links to our handler
        self.i_text_has_selection = False
        def set_i_text_has_selection(b):
            self.i_text_has_selection = bool(b)
        i_text.copyAvailable.connect(set_i_text_has_selection)
        i_text.setContextMenuPolicy(Qt.CustomContextMenu)
        i_text.customContextMenuRequested.connect(self.on_context_menu_for_inputs)
        i_text.setFont(QFont(MONOSPACE_FONT))
        i_text.setReadOnly(True)
        i_text.setTextInteractionFlags(i_text.textInteractionFlags() | Qt.LinksAccessibleByMouse | Qt.LinksAccessibleByKeyboard)
        vbox.addWidget(i_text)


        hbox = QHBoxLayout()
        hbox.setContentsMargins(0,0,0,0)
        vbox.addLayout(hbox)
        hbox.addWidget(QLabel(_("Outputs") + ' (%d)'%len(self.tx.outputs())))

        box_char = "█"
        self.recv_legend = QLabel("<font color=" + ColorScheme.GREEN.as_color(background=True).name() + ">" + box_char + "</font> = " + _("Receiving Address"))
        self.change_legend = QLabel("<font color=" + ColorScheme.YELLOW.as_color(background=True).name() + ">" + box_char + "</font> = " + _("Change Address"))
        f = self.recv_legend.font(); f.setPointSize(f.pointSize()-1)
        self.recv_legend.setFont(f)
        self.change_legend.setFont(f)
        hbox.addStretch(2)
        hbox.addWidget(self.recv_legend)
        hbox.addWidget(self.change_legend)
        self.recv_legend.setHidden(True)
        self.change_legend.setHidden(True)

        self.o_text = o_text = QTextBrowser()
        o_text.setOpenLinks(False)  # disable automatic link opening
        o_text.anchorClicked.connect(self._open_internal_link)  # send links to our handler
        self.o_text_has_selection = False
        def set_o_text_has_selection(b):
            self.o_text_has_selection = bool(b)
        o_text.copyAvailable.connect(set_o_text_has_selection)
        o_text.setContextMenuPolicy(Qt.CustomContextMenu)
        o_text.customContextMenuRequested.connect(self.on_context_menu_for_outputs)
        o_text.setFont(QFont(MONOSPACE_FONT))
        o_text.setReadOnly(True)
        vbox.addWidget(o_text)
        self.cashaddr_signal_slots.append(self.update_io)
        self.main_window.gui_object.cashaddr_toggled_signal.connect(self.update_io)
        self.update_io()

    def update_io(self):
        i_text = self.i_text
        o_text = self.o_text
        ext = QTextCharFormat()
        ext.setToolTip(_("Right-click for context menu"))
        lnk = QTextCharFormat()
        lnk.setToolTip(_('Click to open, right-click for menu'))
        lnk.setAnchor(True)
        lnk.setUnderlineStyle(QTextCharFormat.SingleUnderline)
        rec = QTextCharFormat(lnk)
        rec.setBackground(QBrush(ColorScheme.GREEN.as_color(background=True)))
        chg = QTextCharFormat(lnk)
        chg.setBackground(QBrush(ColorScheme.YELLOW.as_color(True)))
        rec_ct, chg_ct = 0, 0

        def text_format(addr):
            nonlocal rec_ct, chg_ct
            if isinstance(addr, Address) and self.wallet.is_mine(addr):
                if self.wallet.is_change(addr):
                    chg_ct += 1
                    chg2 = QTextCharFormat(chg)
                    chg2.setAnchorHref(addr.to_ui_string())
                    return chg2
                else:
                    rec_ct += 1
                    rec2 = QTextCharFormat(rec)
                    rec2.setAnchorHref(addr.to_ui_string())
                    return rec2
            return ext

        def format_amount(amt):
            return self.main_window.format_amount(amt, whitespaces = True)

        i_text.clear()
        cursor = i_text.textCursor()
        has_schnorr = False
        for i, x in enumerate(self.tx.fetched_inputs() or self.tx.inputs()):
            a_name = f"input {i}"
            for fmt in (ext, rec, chg, lnk):
                fmt.setAnchorNames([a_name])  # anchor name for this line (remember input#); used by context menu creation
            if x['type'] == 'coinbase':
                cursor.insertText('coinbase', ext)
                if isinstance(x.get('value'), int):
                    cursor.insertText(format_amount(x['value']), ext)
            else:
                prevout_hash = x.get('prevout_hash')
                prevout_n = x.get('prevout_n')
                hashn = f'{ prevout_hash[0:6] }...{ prevout_hash[-6:] }:{ prevout_n }'
                # linkify prevout_hash:n, send link to our handler
                lnk2 = QTextCharFormat(lnk)
                lnk2.setAnchorHref(prevout_hash)
                cursor.insertText(hashn, lnk2)
                cursor.insertText((1+max(4-len(str(prevout_n)), 0)) * ' ', ext)  # put spaces/padding
                addr = x.get('address')
                if addr is None:
                    addr_text = _('unknown')
                else:
                    addr_text = addr.to_ui_string()
                cursor.insertText(addr_text, text_format(addr))
                if x.get('value'):
                    cursor.insertText(format_amount(x['value']), ext)
                if self.tx.is_schnorr_signed(i):
                    # Schnorr
                    cursor.insertText(' {}'.format(SCHNORR_SIGIL), ext)
                    has_schnorr = True
            cursor.insertBlock()

        self.schnorr_label.setVisible(has_schnorr)

        o_text.clear()
        cursor = o_text.textCursor()
        for i, tup in enumerate(self.tx.outputs()):
            typ, addr, v = tup
            for fmt in (ext, rec, chg, lnk):
                fmt.setAnchorNames([f"output {i}"])  # anchor name for this line (remember input#); used by context menu creation
            addrstr = addr.to_ui_string()
            cursor.insertText(addrstr, text_format(addr))
            if v is not None:
                if len(addrstr) > 42: # for long outputs, make a linebreak.
                    cursor.insertBlock()
                    addrstr = '\u21b3'
                    cursor.insertText(addrstr, ext)
                # insert enough spaces until column 43, to line up amounts
                cursor.insertText(' '*(43 - len(addrstr)), ext)
                cursor.insertText(format_amount(v), ext)
            cursor.insertBlock()

        # make the change & receive legends appear only if we used that color
        self.recv_legend.setVisible(bool(rec_ct))
        self.change_legend.setVisible(bool(chg_ct))

    @staticmethod
    def _copy_to_clipboard(text, widget):
        if not text and isinstance(widget, QTextEdit):
            widget.copy()
        else:
            qApp.clipboard().setText(text)
        QToolTip.showText(QCursor.pos(), _("Text copied to clipboard"), widget)

    def _open_internal_link(self, target):
        ''' accepts either a str txid, str address, or a QUrl which should be
        of the bare form "txid" and/or "address" -- used by the clickable
        links in the inputs/outputs QTextBrowsers'''
        if isinstance(target, QUrl):
            target = target.toString(QUrl.None_)
        assert target
        if Address.is_valid(target):
            # target was an address, open address dialog
            self.main_window.show_address(Address.from_string(target), parent=self)
        else:
            # target was a txid, open new tx dialog
            self.main_window.do_process_from_txid(txid=target, parent=self)

    def on_context_menu_for_inputs(self, pos):
        i_text = self.i_text
        menu = QMenu()
        global_pos = i_text.viewport().mapToGlobal(pos)

        charFormat, cursor = QTextCharFormat(), i_text.cursorForPosition(pos)
        charFormat = cursor and cursor.charFormat()
        name = charFormat.anchorNames() and charFormat.anchorNames()[0]

        show_list = []
        copy_list = []
        was_cb = False
        try:
            # figure out which input they right-clicked on .. input lines have an anchor named "input N"
            i = int(name.split()[1])  # split "input N", translate N -> int
            inp = (self.tx.fetched_inputs() or self.tx.inputs())[i]
            value = inp.get('value')
            #value_text = (value is not None and (self.main_window.format_amount(value) + " " + self.main_window.base_unit()))
            #menu.addAction(_("Input") + " #" + str(i) + (' - ' + value_text if value else '')).setDisabled(True)
            menu.addAction(_("Input") + " #" + str(i)).setDisabled(True)
            menu.addSeparator()
            if inp.get('type') == 'coinbase':
                menu.addAction(_("Coinbase Input")).setDisabled(True)
                was_cb = True
            else:
                # not coindbase, add options
                u_tup = inp.get('prevout_hash'), inp.get('prevout_n')
                if all(x is not None for x in u_tup):
                    # Copy UTXO
                    utxo = f"{u_tup[0]}:{u_tup[1]}"
                    show_list += [ ( _("Show Prev Tx"), lambda: self._open_internal_link(u_tup[0]) ) ]
                    copy_list += [ ( _("Copy Prevout"), lambda: self._copy_to_clipboard(utxo, i_text) ) ]
                addr = inp.get('address')
                self._add_addr_to_io_menu_lists_for_widget(addr, show_list, copy_list, i_text)
                if isinstance(value, int):
                    value_fmtd = self.main_window.format_amount(value)
                    copy_list += [ ( _("Copy Amount"), lambda: self._copy_to_clipboard(value_fmtd, i_text) ) ]
        except (TypeError, ValueError, IndexError, KeyError, AttributeError) as e:
            self.print_error("Inputs right-click menu exception:", repr(e))

        for item in show_list:
            menu.addAction(*item)
        if show_list and copy_list:
            menu.addSeparator()
        for item in copy_list:
            menu.addAction(*item)

        if show_list or copy_list or was_cb: menu.addSeparator()
        if self.i_text_has_selection:
            # Add this if they have a selection
            menu.addAction(_("Copy Selected Text"), lambda: self._copy_to_clipboard(None, i_text))
        menu.addAction(_("Select All"), i_text.selectAll)
        menu.exec_(global_pos)

    def _add_addr_to_io_menu_lists_for_widget(self, addr, show_list, copy_list, widget):
        if hasattr(addr, 'to_ui_string'):
            addr_text = addr.to_ui_string()
            if isinstance(addr, Address) and self.wallet.is_mine(addr):
                show_list += [ ( _("Address Details"), lambda: self._open_internal_link(addr_text) ) ]
            if isinstance(addr, ScriptOutput):
                action_text = _("Copy Script Text")
            elif isinstance(addr, PublicKey):
                action_text = _("Copy Public Key")
            else:
                action_text = _("Copy Address")
            copy_list += [ ( action_text, lambda: self._copy_to_clipboard(addr_text, widget) ) ]
            # also add script hex copy to clipboard
            if isinstance(addr, ScriptOutput):
                hex_text = addr.to_script().hex() or ''
                if hex_text:
                    copy_list += [ ( _("Copy Script Hex"), lambda: self._copy_to_clipboard(hex_text, widget) ) ]

    def on_context_menu_for_outputs(self, pos):
        o_text = self.o_text
        menu = QMenu()
        global_pos = o_text.viewport().mapToGlobal(pos)

        charFormat, cursor = QTextCharFormat(), o_text.cursorForPosition(pos)
        charFormat = cursor and cursor.charFormat()
        name = charFormat.anchorNames() and charFormat.anchorNames()[0]

        show_list = []
        copy_list = []
        try:
            # figure out which output they right-clicked on .. output lines have an anchor named "output N"
            i = int(name.split()[1])  # split "output N", translate N -> int
            ignored, addr, value = (self.tx.outputs())[i]
            menu.addAction(_("Output") + " #" + str(i)).setDisabled(True)
            menu.addSeparator()
            self._add_addr_to_io_menu_lists_for_widget(addr, show_list, copy_list, o_text)
            if isinstance(value, int):
                value_fmtd = self.main_window.format_amount(value)
                copy_list += [ ( _("Copy Amount"), lambda: self._copy_to_clipboard(value_fmtd, o_text) ) ]
        except (TypeError, ValueError, IndexError, KeyError) as e:
            self.print_error("Outputs right-click menu exception:", repr(e))

        for item in show_list:
            menu.addAction(*item)
        if show_list and copy_list:
            menu.addSeparator()
        for item in copy_list:
            menu.addAction(*item)

        if show_list or copy_list: menu.addSeparator()
        if self.o_text_has_selection:
            # Add this if they have a selection
            menu.addAction(_("Copy Selected Text"), lambda: self._copy_to_clipboard(None, o_text))
        menu.addAction(_("Select All"), o_text.selectAll)
        menu.exec_(global_pos)

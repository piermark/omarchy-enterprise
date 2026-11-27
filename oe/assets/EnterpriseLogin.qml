// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "LoginIdentity.js" as Identity

Rectangle {
    id: root
    width: 640
    height: 480
    color: "#1a1b26"
    property var greeter: typeof sddm === "undefined" ? null : sddm
    property var sessions: typeof sessionModel === "undefined" ? null : sessionModel
    property var settings: typeof config === "undefined" ? ({}) : config
    property var keymap: typeof keyboard === "undefined" ? null : keyboard
    property bool signingIn: false

    Image {
        anchors.fill: parent
        source: root.settings.background || ""
        fillMode: Image.PreserveAspectCrop
        opacity: status === Image.Ready ? 1 : 0
        Behavior on opacity { NumberAnimation { duration: 160 } }
    }

    function authenticate() {
        if (signingIn)
            return
        const account = Identity.qualified(username.text, settings.domain, settings.workgroup,
                                           identity.currentIndex === 1)
        if (!account) {
            message.text = qsTr("Enter a valid username for the selected account type.")
            username.forceActiveFocus()
            return
        }
        if (!password.text) {
            message.text = qsTr("Enter your password.")
            password.forceActiveFocus()
            return
        }
        if (!greeter || session.currentIndex < 0) {
            message.text = qsTr("No desktop session is available.")
            return
        }
        signingIn = true
        message.text = ""
        greeter.login(account, password.text, session.currentIndex)
        password.clear()
    }

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.max(120, Math.min(parent.width - 48, 420))
        spacing: 12

        Label { text: qsTr("Enterprise sign-in"); color: "#eeeeee"; font.pixelSize: 25 }
        TextField {
            id: username
            objectName: "enterprise-username"
            Layout.fillWidth: true
            placeholderText: qsTr("Username")
            focus: true
            KeyNavigation.priority: KeyNavigation.BeforeItem
            KeyNavigation.tab: identity
            inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhPreferLowercase
            onAccepted: password.forceActiveFocus()
        }
        ComboBox {
            id: identity
            objectName: "enterprise-account-type"
            KeyNavigation.tab: password
            Layout.fillWidth: true
            model: [qsTr("Local account"), qsTr("Domain account")]
        }
        TextField {
            id: password
            objectName: "enterprise-password"
            KeyNavigation.tab: session
            Layout.fillWidth: true
            echoMode: TextInput.Password
            placeholderText: qsTr("Password")
            inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText
            onAccepted: root.authenticate()
        }
        ComboBox {
            id: session
            objectName: "enterprise-desktop-session"
            KeyNavigation.tab: keyboardSelector.visible ? keyboardSelector : submit
            Layout.fillWidth: true
            model: root.sessions
            textRole: "name"
            currentIndex: root.sessions && root.sessions.lastIndex >= 0 ? root.sessions.lastIndex : count > 0 ? 0 : -1
        }
        ComboBox {
            id: keyboardSelector
            objectName: "enterprise-keyboard-layout"
            KeyNavigation.tab: submit
            Layout.fillWidth: true
            visible: root.keymap && root.keymap.enabled && count > 1
            model: root.keymap ? root.keymap.layouts : []
            textRole: "longName"
            currentIndex: root.keymap ? root.keymap.currentLayout : -1
            onActivated: function(index) {
                if (root.keymap)
                    root.keymap.currentLayout = index
            }
        }
        Button {
            id: submit
            KeyNavigation.tab: username
            text: qsTr("Sign in")
            enabled: !root.signingIn
            onClicked: root.authenticate()
        }
        Label {
            id: message
            objectName: "enterprise-login-message"
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: "#ffb4a6"
        }
    }

    Component.onCompleted: username.forceActiveFocus()

    Connections {
        target: root.greeter
        function onLoginFailed() {
            root.signingIn = false
            message.text = qsTr("Sign-in failed. Check the account type and try again.")
            password.forceActiveFocus()
        }
    }
}

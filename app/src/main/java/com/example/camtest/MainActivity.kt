package com.example.camtest

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.util.Base64
import android.view.ViewGroup
import android.widget.*
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : Activity() {
    private lateinit var logView: TextView
    private lateinit var ipE: EditText
    private lateinit var portE: EditText
    private lateinit var userE: EditText
    private lateinit var passE: EditText

    private var ip = ""; private var port = ""; private var user = ""; private var pass = ""
    private var ptzUrl = ""; private var profile = ""

    private val prefs by lazy { getSharedPreferences("cam", MODE_PRIVATE) }
    private val PTZ = "http://www.onvif.org/ver20/ptz/wsdl"

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 24, 24, 24) }
        fun edit(hint: String, key: String, def: String, pw: Boolean = false) = EditText(this).apply {
            this.hint = hint; setText(prefs.getString(key, def))
            if (pw) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            root.addView(this)
        }
        ipE = edit("Kamera IP", "ip", "192.168.1.33")
        portE = edit("Port", "port", "5000")
        userE = edit("Kullanici adi", "user", "admin")
        passE = edit("Sifre", "pass", "", true)
        fun btn(t: String, f: () -> Unit) = Button(this).apply { text = t; setOnClickListener { f() }; root.addView(this) }
        btn("1) Baglan") { run { connect() } }
        btn("2) Su anki konumu KAPI olarak kaydet") { run { savePreset() } }
        btn("3) Kapiya git") { run { gotoPreset() } }
        btn("4) Konumu oku") { run { status() } }
        btn("5) Presetleri listele") { run { presets() } }
        btn("6) Sola cevir (1 sn)") { run { moveLeft() } }
        logView = TextView(this)
        val sv = ScrollView(this).apply { addView(logView) }
        root.addView(sv, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
    }

    private fun log(s: String) = runOnUiThread { logView.append(s + "\n\n") }

    private fun run(f: () -> Unit) {
        ip = ipE.text.toString().trim(); port = portE.text.toString().trim()
        user = userE.text.toString().trim(); pass = passE.text.toString()
        prefs.edit().putString("ip", ip).putString("port", port).putString("user", user).putString("pass", pass).apply()
        Thread {
            try { f() } catch (e: Exception) { log("HATA: " + e) }
        }.start()
    }

    private fun soap(url: String, body: String): String {
        val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
        val created = sdf.format(Date())
        val md = MessageDigest.getInstance("SHA-1")
        md.update(nonce); md.update(created.toByteArray()); md.update(pass.toByteArray())
        val digest = Base64.encodeToString(md.digest(), Base64.NO_WRAP)
        val n64 = Base64.encodeToString(nonce, Base64.NO_WRAP)
        val env = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header>" +
            "<Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken>" +
            "<Username>$user</Username>" +
            "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">$digest</Password>" +
            "<Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">$n64</Nonce>" +
            "<Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">$created</Created>" +
            "</UsernameToken></Security></s:Header><s:Body>$body</s:Body></s:Envelope>"
        val bytes = env.toByteArray()
        val m = Regex("<(\\w+) xmlns=\"([^\"]+)\"").find(body)
        val action = if (m != null) m.groupValues[2] + "/" + m.groupValues[1] else ""
        val c = URL(url).openConnection() as HttpURLConnection
        c.requestMethod = "POST"; c.doOutput = true; c.connectTimeout = 5000; c.readTimeout = 8000
        c.setRequestProperty("Content-Type", "application/soap+xml; charset=utf-8; action=\"$action\"")
        c.setRequestProperty("Connection", "close")
        c.setFixedLengthStreamingMode(bytes.size)
        c.outputStream.use { it.write(bytes) }
        val code = c.responseCode
        val text = (if (code < 400) c.inputStream else c.errorStream)?.bufferedReader()?.readText() ?: ""
        if (code >= 400) throw RuntimeException("HTTP $code: " + text.take(300))
        return text
    }

    private fun connect() {
        val dev = "http://$ip:$port/onvif/device_service"
        val caps = soap(dev, "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>All</Category></GetCapabilities>")
        val rx = { tag: String -> Regex("<(?:\\w+:)?$tag>\\s*<(?:\\w+:)?XAddr>([^<]+)<").find(caps)?.groupValues?.get(1) }
        val media = rx("Media") ?: throw RuntimeException("Media adresi yok")
        val prof = soap(media, "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>")
        profile = Regex("Profiles[^>]*token=\"([^\"]+)\"").find(prof)?.groupValues?.get(1)
            ?: throw RuntimeException("Profil bulunamadi")
        ptzUrl = rx("PTZ") ?: dev
        log("BAGLANDI\nPTZ adresi: $ptzUrl\nProfil: $profile")
    }

    private fun need() { if (profile.isEmpty() || ptzUrl.isEmpty()) connect() }

    private fun savePreset() {
        need()
        val old = prefs.getString("presetToken", null)
        val tok = if (old != null) "<PresetToken>$old</PresetToken>" else ""
        val r = soap(ptzUrl, "<SetPreset xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken><PresetName>door</PresetName>$tok</SetPreset>")
        val t = Regex("PresetToken>([^<]+)<").find(r)?.groupValues?.get(1) ?: old
        if (t != null) prefs.edit().putString("presetToken", t).apply()
        log("KAPI KAYDEDILDI. Token: $t")
    }

    private fun gotoPreset() {
        need()
        val t = prefs.getString("presetToken", null) ?: throw RuntimeException("Once 2) ile kapiyi kaydet")
        soap(ptzUrl, "<GotoPreset xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken><PresetToken>$t</PresetToken></GotoPreset>")
        log("Kapiya git komutu gonderildi")
    }

    private fun status() {
        need()
        val r = soap(ptzUrl, "<GetStatus xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken></GetStatus>")
        val m = Regex("PanTilt[^>]*x=\"([^\"]+)\"[^>]*y=\"([^\"]+)\"").find(r)
        if (m != null) log("Konum pan=${m.groupValues[1]} tilt=${m.groupValues[2]}")
        else log("Konum bilgisi YOK. Ham cevap:\n" + r.take(600))
    }

    private fun presets() {
        need()
        val r = soap(ptzUrl, "<GetPresets xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken></GetPresets>")
        log("Presetler:\n" + r.take(700))
    }

    private fun moveLeft() {
        need()
        soap(ptzUrl, "<ContinuousMove xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken><Velocity><PanTilt x=\"-0.5\" y=\"0\" xmlns=\"http://www.onvif.org/ver10/schema\"/></Velocity></ContinuousMove>")
        Thread.sleep(1000)
        soap(ptzUrl, "<Stop xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken><PanTilt>true</PanTilt><Zoom>false</Zoom></Stop>")
        log("Sola cevirme komutu gonderildi")
    }
}

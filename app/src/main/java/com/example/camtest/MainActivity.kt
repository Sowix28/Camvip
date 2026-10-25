package com.example.camtest

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.util.Base64
import android.view.ViewGroup
import android.view.WindowManager
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
    private lateinit var slamE: EditText
    private lateinit var panE: EditText
    private lateinit var tiltE: EditText
    private lateinit var minE: EditText
    private lateinit var autoBtn: Button

    private var ip = ""; private var port = ""; private var user = ""; private var pass = ""
    private var ptzUrl = ""; private var profile = ""
    private var imgUrl = ""; private var vsToken = ""
    private var slamS = 12; private var panMs = 3000; private var tiltMs = 1000; private var autoMin = 3
    @Volatile private var autoOn = false
    @Volatile private var keepDay = false

    private val prefs by lazy { getSharedPreferences("cam", MODE_PRIVATE) }
    private val PTZ = "http://www.onvif.org/ver20/ptz/wsdl"
    private val IMG = "http://www.onvif.org/ver20/imaging/wsdl"

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 24, 24, 24) }
        fun edit(hint: String, key: String, def: String, pw: Boolean = false, num: Boolean = false) = EditText(this).apply {
            this.hint = hint; setText(prefs.getString(key, def))
            if (pw) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            if (num) inputType = InputType.TYPE_CLASS_NUMBER
            root.addView(this)
        }
        ipE = edit("Kamera IP", "ip", "192.168.1.33")
        portE = edit("Port", "port", "5000")
        userE = edit("Kullanici adi", "user", "admin")
        passE = edit("Sifre", "pass", "", pw = true)
        slamE = edit("Uca dayanma suresi (sn)", "slam", "12", num = true)
        panE = edit("Sagdan kapiya gelme suresi (ms)", "pan", "3000", num = true)
        tiltE = edit("Yukari kapiya gelme suresi (ms)", "tilt", "1000", num = true)
        minE = edit("Otomatik donus araligi (dk)", "min", "3", num = true)
        fun btn(t: String, f: () -> Unit) = Button(this).apply { text = t; setOnClickListener { f() }; root.addView(this) }
        btn("1) Baglan") { run { connect() } }
        btn("2) Sola cevir (3 sn)") { run { move(-0.5, 0.0, 3000); log("Sola cevirme bitti") } }
        btn("3) Su anki konumu HOME kaydet") { run { homeSet() } }
        btn("4) HOME'a git") { run { homeGo() } }
        btn("5) Kapiya git (sureli yontem)") { run { goDoor() } }
        autoBtn = btn("6) Otomatik donus: KAPALI") { run { toggleAuto() } }
        btn("7) Gece gorusunu KAPAT") { run { keepDay = true; setIr("ON"); log("Gece gorusu KAPALI (gunduz modu) istendi") } }
        btn("8) Gece gorusu OTOMATIK") { run { keepDay = false; setIr("AUTO"); log("Gece gorusu OTOMATIK istendi") } }
        logView = TextView(this)
        root.addView(logView)
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun log(s: String) = runOnUiThread { logView.append(s + "\n\n") }

    private fun run(f: () -> Unit) {
        ip = ipE.text.toString().trim(); port = portE.text.toString().trim()
        user = userE.text.toString().trim(); pass = passE.text.toString()
        slamS = slamE.text.toString().toIntOrNull() ?: 12
        panMs = panE.text.toString().toIntOrNull() ?: 3000
        tiltMs = tiltE.text.toString().toIntOrNull() ?: 1000
        autoMin = minE.text.toString().toIntOrNull() ?: 3
        prefs.edit().putString("ip", ip).putString("port", port).putString("user", user).putString("pass", pass)
            .putString("slam", slamS.toString()).putString("pan", panMs.toString())
            .putString("tilt", tiltMs.toString()).putString("min", autoMin.toString()).apply()
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
        vsToken = Regex("SourceToken>([^<]+)<").find(prof)?.groupValues?.get(1) ?: ""
        ptzUrl = rx("PTZ") ?: dev
        imgUrl = rx("Imaging") ?: ""
        log("BAGLANDI\nPTZ adresi: $ptzUrl\nProfil: $profile\nImaging: $imgUrl\nVideoSource: $vsToken")
    }

    private fun need() { if (profile.isEmpty() || ptzUrl.isEmpty()) connect() }

    private fun move(x: Double, y: Double, ms: Long) {
        need()
        val body = "<ContinuousMove xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken><Velocity><PanTilt x=\"$x\" y=\"$y\" xmlns=\"http://www.onvif.org/ver10/schema\"/></Velocity></ContinuousMove>"
        val end = System.currentTimeMillis() + ms
        do {
            soap(ptzUrl, body)
            Thread.sleep(300)
        } while (System.currentTimeMillis() < end)
        soap(ptzUrl, "<Stop xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken><PanTilt>true</PanTilt><Zoom>false</Zoom></Stop>")
    }

    private fun setIr(mode: String) {
        need()
        if (imgUrl.isEmpty() || vsToken.isEmpty()) throw RuntimeException("Kamera Imaging servisi/video kaynagi bildirmiyor")
        soap(imgUrl, "<SetImagingSettings xmlns=\"$IMG\"><VideoSourceToken>$vsToken</VideoSourceToken>" +
            "<ImagingSettings><IrCutFilter xmlns=\"http://www.onvif.org/ver10/schema\">$mode</IrCutFilter></ImagingSettings>" +
            "<ForcePersistence>true</ForcePersistence></SetImagingSettings>")
    }

    private fun homeSet() {
        need()
        soap(ptzUrl, "<SetHomePosition xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken></SetHomePosition>")
        log("HOME kaydedildi (kamera kabul etti)")
    }

    private fun homeGo() {
        need()
        soap(ptzUrl, "<GotoHomePosition xmlns=\"$PTZ\"><ProfileToken>$profile</ProfileToken></GotoHomePosition>")
        log("HOME'a git komutu gonderildi")
    }

    private fun goDoor() {
        need()
        log("Kapiya donuluyor...")
        move(-0.5, 0.0, slamS * 1000L)
        move(0.0, -0.5, maxOf(4, slamS / 2) * 1000L)
        move(0.5, 0.0, panMs.toLong())
        move(0.0, 0.5, tiltMs.toLong())
        log("Kapiya donus bitti")
    }

    private fun toggleAuto() {
        if (autoOn) {
            autoOn = false
            runOnUiThread { autoBtn.text = "6) Otomatik donus: KAPALI" }
            log("Otomatik donus kapatildi")
            return
        }
        autoOn = true
        runOnUiThread { autoBtn.text = "6) Otomatik donus: ACIK" }
        log("Otomatik donus acildi: $autoMin dk'da bir")
        while (autoOn) {
            try { goDoor() } catch (e: Exception) { log("HATA: " + e) }
            if (keepDay) { try { setIr("ON") } catch (e: Exception) { log("IR HATA: " + e) } }
            var waited = 0
            while (autoOn && waited < autoMin * 60) { Thread.sleep(1000); waited++ }
        }
    }
}

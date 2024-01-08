rule contacts_fileshare_or_CDN {
    meta:
        author = "Ryan <@IntelCorgi>"
        version = "1.1"
        100days = "Day 7"
        date = "07 January 2023"
        description = "Check if file contacts a fileshare/cdn to grab a payload"
    strings:
        $a1 = "cdn.discordapp.com/attachments/" ascii wide
        $a2 = "onedrive.live.com/" ascii wide
        $a3 = "privatlab.com/s/s/" ascii wide
        $a4 = "privatlab.com/s/v/" ascii wide
        $a5 = "transfer.sh/get/" ascii wide
        $a6 = "anonfiles.com" ascii wide
        $a7 = "sendspace.com/file/" ascii wide
        $a8 = "fex.net/get/" ascii wide
        $a9 = "mediafire.com/file/" ascii wide
        $a10 = "pancake.vn/" ascii wide
        $a11 = "my.sharepoint[.]com/:u:/" ascii wide
        $a12 = "s3.amazonaws[.]com/" ascii wide
        $a13 = "github[.]com/" ascii wide
        $a14 = "raw.githubusercontent[.]com/" ascii wide
        $a15 = "gist.githubusercontent[.]com/" ascii wide
        $a16 = "weebly[.]com/uploads" ascii wide
        $a17 = "dropbox[.]com/scl/fi" ascii wide
        $a18 = "drive.google[.]com/uc?export=download&id=" ascii wide
        $a19 = "drive.google[.]com/file/d/" ascii wide
        $a20 = "drive.google[.]com/u/0/" ascii wide
        $a21 = "box[.]com/s/" ascii wide
        $a22 = "box[.]com/file/" ascii wide
        $a23 = "box[.]com/shared/" ascii wide
        $a24 = "blob.core.windows[.]net/" ascii wide
    condition:
        any of $a
}
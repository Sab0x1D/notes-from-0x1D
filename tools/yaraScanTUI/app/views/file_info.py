from textual.widgets import Static

class FileInfo(Static):
    def update_info(self, info):
        lines = []
        if info:
            lines.append(f"[b]File:[/b] {info.path.name}")
            lines.append(f"Path: {info.path}")
            lines.append(f"Size: {info.size} bytes")
            lines.append(f"SHA256: {info.sha256}")
            lines.append(f"SHA1: {info.sha1}")
            lines.append(f"MD5: {info.md5}")
            if info.pe:
                lines.append(f"PE: sections={info.pe.get('sections')} machine={info.pe.get('machine')}")
        else:
            lines.append("No file loaded.")
        self.update("\n".join(lines))

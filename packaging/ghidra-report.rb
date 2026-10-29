class GhidraReport < Formula
  desc "Automated binary analysis, threat triage, and firmware carving toolkit"
  homepage "https://github.com/Ekco-S64QTN6/ghidra-tools"
  url "https://github.com/Ekco-S64QTN6/ghidra-tools/archive/refs/tags/v#{version}.tar.gz"
  # Release tag/checksum not published yet; replace before installing or releasing the formula.
  sha256 "SKIP"
  license "MIT"

  depends_on "openjdk@25"
  depends_on "python@3.12"
  depends_on "pyyaml"
  depends_on "sqlite"

  def install
    libexec.install "ghidra-report.sh", "run-headless.sh", "VERSION", "requirements-rules.txt"
    libexec.install "scripts", "rules", "schemas"

    launcher = File.read("packaging/ghidra-report-launcher.sh.in")
    launcher.gsub!("@APP_ROOT@", libexec.to_s)
    (bin/"ghidra-report").write(launcher)
    (bin/"ghidra-report").chmod 0755

    man1.install "ghidra-report.1"
  end

  test do
    assert_match "ghidra-report v#{version}", shell_output("#{bin}/ghidra-report --help")
  end
end

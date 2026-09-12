class GhidraReport < Formula
  desc "Automated binary analysis, threat triage, and firmware carving toolkit"
  homepage "https://github.com/ghidra-tools/ghidra-report"
  url "https://github.com/ghidra-tools/ghidra-report/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "SKIP"
  license "MIT"

  depends_on "openjdk@21"
  depends_on "python@3.12"
  depends_on "sqlite"

  def install
    bin.install "ghidra-report.sh" => "ghidra-report"
    man1.install "ghidra-report.1"
    pkgshare.install "scripts", "rules", "run-headless.sh"
  end

  test do
    assert_match "ghidra-report v0.2.0", shell_output("#{bin}/ghidra-report --help")
  end
end

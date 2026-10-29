class GhidraReport < Formula
  desc "Automated binary analysis, threat triage, and firmware carving toolkit"
  homepage "https://github.com/Ekco-S64QTN6/ghidra-tools"
  url "https://github.com/Ekco-S64QTN6/ghidra-tools/archive/refs/tags/v#{version}.tar.gz"
  # Release tag/checksum not published yet; replace before installing or releasing the formula.
  sha256 "SKIP"
  license "MIT"

  depends_on "openjdk@25"
  depends_on "python@3.12"
  depends_on "sqlite"

  def install
    bin.install "ghidra-report.sh" => "ghidra-report"
    man1.install "ghidra-report.1"
    pkgshare.install "scripts", "rules", "run-headless.sh"
  end

  test do
    assert_match "ghidra-report v#{version}", shell_output("#{bin}/ghidra-report --help")
  end
end

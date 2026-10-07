# Minimal Fedora Kickstart sample: this file is NOT a Keep Shipping site file.
# It exists to prove the grammar never claims `*.ks` — Kickstart belongs to
# Red Hat and to the people who write it.
lang en_US.UTF-8
keyboard us
timezone UTC --utc
rootpw --lock
bootloader /boot/efi
clearpart --all --initlabel
autopart

%packages
@core
vim-enhanced

%end

%post
log "kickstart finished"
%end
const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

document.addEventListener('DOMContentLoaded', () => {
    const toggleButton = document.getElementById('protection-toggle');

    browserAPI.storage.local.get(['isProtectionOn'], (result) => {
        if (result.isProtectionOn !== 'undefined'){
            toggleButton.checked = result.isProtectionOn;
        }else{
            toggleButton.checked = true;
        }
    });

    toggleButton.addEventListener('change', (e) => {
        const isSwitchOn = e.target.checked;
        browserAPI.storage.local.set({isProtectionOn: isSwitchOn});
    });
});
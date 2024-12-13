window.onload = function () {
    // Your code here
    console.log("Window loaded");

    const token = "{{ .Token }}";

    // set the cookie on the top level domain but with a more specific path
    document.cookie = `_gorilla_csrf=${token}; path=/submit; domain=example.com;`;

    // create a malicious form
    const form = window.document.createElement("form");
    form.action = "https://foo.example.com/submit";
    form.method = "post";
    form.innerHTML = `<input type="hidden" name="_gorilla_token" value="${token}" />`;


};

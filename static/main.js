$(document).ready(function () {

    if(document.location.pathname.match(/\/$/)) {
        $("#ocsp-submit-button").click(function (event) {

            event.preventDefault();
            var form = $('#certificate-input-form')[0];
            var data = new FormData(form);
            data.append("action", "Check OCSP Response");

            $.ajax({
                type: "POST",
                enctype: 'multipart/form-data',
                url: "response-check",
                data: data,
                processData: false,
                contentType: false,
                cache: false,
                timeout: 600000,
                success: function (data) {

                    localStorage.setItem('ocsp-response', data);
                    //console.log(data)
                    window.location.href = window.location.protocol + "//" + window.location.host + "/response"
                    //console.log(window.location)
                },
                error: function (e) {

                    console.log("ERROR : ", e);

                }
            });

        });
    }
    
    else if(document.location.pathname.match(/\/response$/)){
        
        var json_response = localStorage.getItem('ocsp-response');
        var json_obj = JSON.parse(json_response)

        var ul = document.getElementById("lint-list");
        for (var key in json_obj){
            if (json_obj.hasOwnProperty(key)){
                ul.appendChild(return_li(json_obj[key], key));
            }
        }

    }

});

function return_li(data, key, flag){

    var list = document.createElement('li');
    list.setAttribute("id", key)
    var img = document.createElement('img');
    img.setAttribute("src", "/static/images/success.png")
    img.setAttribute("height", "32px")
    img.setAttribute("width", "32px")
    list.appendChild(img)
    var p = document.createElement('p')
    p.innerHTML = data
    list.append(p)
    return list
}
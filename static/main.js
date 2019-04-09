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
                if (key == "NoFailure"){
                    ul.appendChild(return_li(key, json_obj[key], 0))
                    break;
                }
                else{
                    ul.appendChild(return_li(key, json_obj[key], 1));
                }
            }
        }

    }

});

function return_li(key, data, flag){

    var list_item = document.createElement('li');
    list_item.setAttribute("id", key);
    list_item.setAttribute("class", "lint-list-item");
    var img = document.createElement('img');
    if (flag == 0){
        img.setAttribute("src", "/static/images/success.png");
    }
    else{
        img.setAttribute("src", "/static/images/error.png")
    }
    img.setAttribute("height", "25px");
    img.setAttribute("width", "25px");
    list_item.appendChild(img);
    var p = document.createElement('p');
    p.innerHTML = data;
    list_item.append(p);
    return list_item;
}
window.onload = ()=>{
    const loader = document.getElementById('loader');
    loader.classList.add('loaded');
}
//safari対策
window.onpageshow = function (event) {
    if (event.persisted) {
        window.location.reload();
    }
};
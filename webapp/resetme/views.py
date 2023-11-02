from django.shortcuts import render
from django.http import HttpResponse
from .forms import UserForm

def index(request):
    #return HttpResponse("Hello, world. You're at the resetme index.")
    #return render(request, 'index.html')
    #username = request.POST.get('username')
    # if this is a POST request we need to process the form data
    if request.method == "POST":
        submitbutton= request.POST.get("submit")
        username = ''
        form= UserForm(request.POST or None)
        if form.is_valid():
            username = form.cleaned_data.get("username")
        
        context= {'form': form, 'username': username, 'submitbutton': submitbutton}
        
        return render(request, 'index.html', context)

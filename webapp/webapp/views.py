from django.shortcuts import redirect


def redirect_to_resetme(request):
    return redirect('index', permanent=True)

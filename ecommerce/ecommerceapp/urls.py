from django.urls import path
from ecommerceapp import views

urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name="about"),
    path('contact/', views.contact, name="contact"),
    path('checkout/', views.checkout, name='checkout'),
    path('profile/', views.profile, name='profile'),
    path('handlerequest/', views.handlerequest, name='handlerequest'),
    path('product/<int:myid>/', views.productView, name='productView'),
 path("search-suggest/", views.search_suggest, name="search_suggest"),
   path("search/", views.search, name="search"),
]

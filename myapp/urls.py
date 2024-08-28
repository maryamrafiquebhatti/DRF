from django.urls import path
from .views import product_list, product_detail, product_csv, RegisterUser, LoginUser
from rest_framework.authtoken.views import obtain_auth_token


urlpatterns = [
    path('products/', product_list, name='product-list'),
    path('products/<int:pk>/', product_detail, name='product-detail'),
    path('products/csv/', product_csv, name='product-csv'),
    path('register/', RegisterUser.as_view(), name='register'),
    path('login/', LoginUser.as_view(), name='login'),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),

]
